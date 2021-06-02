import gc
import queue
from abc import ABC, abstractmethod
from traceback import TracebackException
from typing import List, Optional, Generator

from sslyze import ServerConnectivityInfo, ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed
from sslyze.scanner._connectivity_testing import ServerConnectivityTestingLogic
from sslyze.scanner._queued_server_scan import ProducerThread, NoMoreServerScanRequestsSentinel, ReachableServerScanRequest
from sslyze.scanner.server_scan_request import ServerScanResult, ServerScanRequest, ServerScanResponse, \
    ConnectivityError


# TODO: Pass scan_request?
# Could be turned into a typing.Protocol once we stop supporting Python 3.7
class ScannerObserver(ABC):

    @abstractmethod
    def server_connectivity_test_failed(
        self,
        server_scan_request: ServerScanRequest,
        # TODO: tls_probing_error?
        connectivity_error: ConnectionToServerFailed
    ) -> None:
        """The Scanner found a server that it could not connect to; no scans will be performed against this server.
        """

    @abstractmethod
    def server_connectivity_test_succeeded(
        self,
        server_scan_request: ServerScanRequest,
        tls_probing_result: ServerTlsProbingResult
    ) -> None:
        """The Scanner found a server that it was able to connect to; scans will be run against this server.
        """

    @abstractmethod
    def server_scan_completed(self, server_scan_response: ServerScanResponse) -> None:
        """The Scanner has finished scanning one single server.
        """

    @abstractmethod
    def all_server_scans_completed(self, total_scan_time: float) -> None:
        """The Scanner has finished scanning all the supplied servers and will now exit.
        """


class Scanner:
    def __init__(
        self,
        per_server_concurrent_connections_limit: Optional[int] = None,
        concurrent_server_scans_limit: Optional[int] = None,
    ):
        # Setup default values
        if per_server_concurrent_connections_limit is None:
            final_per_server_concurrent_connections_limit = 5
        else:
            final_per_server_concurrent_connections_limit = per_server_concurrent_connections_limit
        self._per_server_concurrent_connections_count = final_per_server_concurrent_connections_limit

        if concurrent_server_scans_limit is None:
            final_concurrent_server_scans_limit = 10
        else:
            final_concurrent_server_scans_limit = concurrent_server_scans_limit
        self._concurrent_server_scans_count = final_concurrent_server_scans_limit

        self._connectivity_tester = ServerConnectivityTestingLogic(self._concurrent_server_scans_count)

    @property
    def _are_server_scans_ongoing(self) -> bool:
        # TODO
        return True if self._producer_thread else False

    def start_scans(self, server_scan_requests: List[ServerScanRequest]) -> None:
        if self._are_server_scans_ongoing:
            raise ValueError("Already submitted scan requests")

        if not server_scan_requests:
            raise ValueError("Submitted emtpy list of server_scan_requests")

        # TODO: Connectivity testing
        self._connectivity_tester.start_work(server_scan_requests)

    def get_results(self, observer: Optional[ScannerObserver] = None) -> Generator[ServerScanResult, None, None]:
        if not self._are_server_scans_ongoing:
            raise ValueError("No scan requests have been submitted")

        # Initialize the logic for running scan commands
        reachable_server_scan_requests_queue: "queue.Queue[ReachableServerScanRequest]" = queue.Queue()
        server_scan_responses_queue: "queue.Queue[ServerScanResponse]" = queue.Queue()
        producer_thread = ProducerThread(
            concurrent_server_scans_count=self._concurrent_server_scans_count,
            per_server_concurrent_connections_count=self._per_server_concurrent_connections_count,
            reachable_server_scan_requests_queue_in=reachable_server_scan_requests_queue,
            server_scan_responses_queue_out=server_scan_responses_queue,
        )
        producer_thread.start()

        # Wait for all connectivity testing to finish
        def connectivity_test_success_callback(
            server_scan_request: ServerScanRequest, tls_probing_result: ServerTlsProbingResult
        ) -> None:
            if observer:
                observer.server_connectivity_test_succeeded(server_scan_request, tls_probing_result)

            # Since the server is reachable, queue the actual scan commands
            reachable_server_scan_requests_queue.put(
                ReachableServerScanRequest(server_scan_request, tls_probing_result))

        def connectivity_test_failure_callback(
            server_scan_request: ServerScanRequest, connectivity_error: ConnectionToServerFailed
        ) -> None:
            if observer:
                observer.server_connectivity_test_failed(server_scan_request, connectivity_error)

            # Since the server is not reachable, there is nothing to scan
            server_scan_responses_queue.put(
                ServerScanResponse(
                    request=server_scan_request,
                    connectivity_error=ConnectivityError(
                        exception_trace=TracebackException.from_exception(connectivity_error),
                    ),
                    result=None,
                )
            )

        self._connectivity_tester.complete_all_work(
            success_callback=connectivity_test_success_callback, failure_callback=connectivity_test_failure_callback
        )

        # Once we get here, all the scans to servers that are reachable have been queued
        reachable_server_scan_requests_queue.put(NoMoreServerScanRequestsSentinel())  # type: ignore

        # Wait for all scan commands to finish
        # For servers that are reachable, start dispatching scan commands
        while True:
            server_scan_result = server_scan_responses_queue.get(block=True)
            server_scan_responses_queue.task_done()
            if isinstance(server_scan_result, NoMoreServerScanRequestsSentinel):
                # No more scans to run
                break

            yield server_scan_result
            # Force garbage collection here so that all the objects related to the server scan that completed just now
            # get removed from memory. Without this, SSLyze's memory usage balloons as more scans get queued
            # https://github.com/nabla-c0d3/sslyze/issues/511.
            gc.collect()

        # All done with the scans
        server_scan_responses_queue.join()
        producer_thread.join()
        return
