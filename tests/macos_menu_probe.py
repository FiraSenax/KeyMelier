"""Exercise native menu callbacks on the real Cocoa thread, without keys or user data."""
import faulthandler
import json
import sys
import threading
import time
from pathlib import Path


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import webview
    from PyObjCTools import AppHelper
    from keymelier_core.menubar import MenuBar

    window = webview.create_window(
        "KeyMelier menu regression test",
        html="""<html><body>Isolated menu test<script>
            window.actions = [];
            window.__kmAbout = () => window.actions.push('about');
            window.__kmCheckUpdates = () => window.actions.push('updates');
            window.__kmSelectToken = id => window.actions.push(id);
        </script></body></html>""",
        width=420, height=240,
    )
    menu = MenuBar(None, window, Path("unused"))
    failures = []
    token = 'test-key"\\\n\u2028'

    def exercise():
        try:
            window.events.loaded.wait()
            # An unfixed main-thread deadlock cannot close the window normally.
            faulthandler.dump_traceback_later(15, exit=True)
            expected = []
            for action, value in ((menu._show_about, "about"),
                                  (menu._check_updates, "updates"),
                                  (lambda: menu._open(token), token)):
                returned = threading.Event()

                def invoke(action=action, returned=returned):
                    try:
                        assert threading.current_thread() is threading.main_thread()
                        action()
                    except Exception as error:
                        failures.append(type(error).__name__)
                    finally:
                        returned.set()

                AppHelper.callAfter(invoke)
                assert returned.wait(5), "Native menu callback blocked the UI thread"
                expected.append(value)
                deadline = time.monotonic() + 5
                while window.evaluate_js("window.actions") != expected:
                    assert time.monotonic() < deadline, "Menu action did not reach the page"
                    time.sleep(0.02)
                assert not failures, failures
                print(f"PASS native menu action {len(expected)}", flush=True)
        except Exception as error:
            failures.append(str(error))
        finally:
            # Keep the watchdog armed until the native event loop really exits.
            window.destroy()

    webview.start(exercise)
    faulthandler.cancel_dump_traceback_later()
    if failures:
        print(json.dumps(failures), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
