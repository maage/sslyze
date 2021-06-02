import queue
import threading
from typing import Tuple, Union, List, Callable

from sslyze import ServerConnectivityTester, ServerConnectivityInfo, ServerScanRequest, ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed


_ServerConnectivityTestingResult = Union[ServerTlsProbingResult, ConnectionToServerFailed]


ConnectivityTestingSuccessCallback = Callable[[ServerScanRequest, ServerTlsProbingResult], None]
ConnectivityTestingFailureCallback = Callable[[ServerScanRequest, ConnectionToServerFailed], None]


# TODO: TlsProbing?
class ServerConnectivityTestingLogic:
    """Helper class to ensure SSLyze can connect to the servers, before it tries to scan them.
    """

    def __init__(self, concurrent_server_scans_count: int) -> None:
        self._scan_requests_queue: "queue.Queue[ServerScanRequest]" = queue.Queue()
        self._results_queue: "queue.Queue[Tuple[ServerScanRequest, _ServerConnectivityTestingResult]]" = queue.Queue()
        self._all_worker_threads = [
            _ConnectivityTestingThread(
                scan_requests_queue_in=self._scan_requests_queue,
                results_queue_out=self._results_queue,
            )
            for _ in range(concurrent_server_scans_count)
        ]
        self._work_is_ongoing = False

    def start_work(self, server_scan_requests: List[ServerScanRequest]):
        assert not self._work_is_ongoing

        self._work_is_ongoing = True
        # Start the threads
        for worker_thread in self._all_worker_threads:
            worker_thread.start()
        # Queue the work
        for request in server_scan_requests:
            self._scan_requests_queue.put(request)

    def complete_all_work(
        self,
        success_callback: ConnectivityTestingSuccessCallback,
        failure_callback: ConnectivityTestingFailureCallback
    ) -> None:
        while True:
            result = self._results_queue.get(block=True)
            self._results_queue.task_done()
            if isinstance(result, _ConnectivityTestingThread.NoMoreWorkSentinel):
                # All done with connectivity testing
                # Ensure a clean shutdown of the connectivity testing logic
                self._scan_requests_queue.join()
                self._results_queue.join()

                for worker_thread in self._all_worker_threads:
                    worker_thread.join()

                break
            else:
                scan_request, connectivity_result = result
                if isinstance(connectivity_result, ConnectionToServerFailed):
                    failure_callback(scan_request, connectivity_result)
                elif isinstance(connectivity_result, ServerTlsProbingResult):
                    success_callback(scan_request, connectivity_result)


class _ConnectivityTestingThread(threading.Thread):

    class NoMoreWorkSentinel:
        pass

    def __init__(
        self,
        scan_requests_queue_in: "queue.Queue[ServerScanRequest]",
        results_queue_out: "queue.Queue[Tuple[ServerScanRequest, _ServerConnectivityTestingResult]]"
    ):
        super().__init__()
        self._scan_requests_queue_in = scan_requests_queue_in
        self._results_queue_out = results_queue_out
        self.daemon = True  # Shutdown the thread if the program is exiting early (ie. ctrl+c)

    def run(self) -> None:
        while True:
            scan_request = self._scan_requests_queue_in.get(block=True)
            if isinstance(scan_request, self.NoMoreWorkSentinel):
                self._results_queue_out.put(self.NoMoreWorkSentinel())  # type: ignore
                self._scan_requests_queue_in.task_done()

                # No more jobs to complete - shutdown the thread
                break

            try:
                tls_probing_result = ServerConnectivityTester().perform(
                    server_location=scan_request.server_location,
                    network_configuration=scan_request.network_configuration
                )
                self._results_queue_out.put((scan_request, tls_probing_result))
            except ConnectionToServerFailed as e:
                self._results_queue_out.put((scan_request, e))

            self._scan_requests_queue_in.task_done()
