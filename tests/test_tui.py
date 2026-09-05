import asyncio

from textual.widgets import DataTable, Select, Static, TabbedContent

from nandatown.tui import TownApp


def run_async(coro):
    return asyncio.run(coro)


def test_app_mounts_with_all_tabs(tmp_path):
    async def go():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test() as pilot:
            for tab in ["tab-town", "tab-run", "tab-agents",
                        "tab-protocols", "tab-services", "tab-evidence"]:
                assert app.query_one(f"#{tab}")
            status = app.query_one("#town-status").render()
            assert "12 protocol layers" in str(status)
            await pilot.pause()

    run_async(go())


def test_town_tab_links_to_the_site(tmp_path):
    async def go():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test() as pilot:
            site = app.query_one("#town-site", Static).render()
            assert "nanda.town" in str(site)
            assert any("website" in str(b) for b in app.BINDINGS)
            await pilot.pause()

    run_async(go())


def test_lab_run_from_the_run_tab(tmp_path):
    async def go():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test() as pilot:
            app.query_one(TabbedContent).active = "tab-run"
            await pilot.pause()
            app.query_one("#run-target", Select).value = "voting"
            await pilot.pause()
            await pilot.click("#run-go")
            await app.workers.wait_for_complete()
            await pilot.pause()
            stages = app.query_one("#run-stages", DataTable)
            assert stages.row_count >= 4
            bundles = app.query_one("#bundle-table", DataTable)
            assert bundles.row_count == 1

    run_async(go())


def test_web_server_builds_with_ui_command(tmp_path):
    from nandatown.tui import build_web_server

    server = build_web_server(out_dir=str(tmp_path), port=8931)
    assert "nandatown.cli ui" in server.command
    assert str(tmp_path) in server.command
    assert server.port == 8931


def test_evidence_verify_from_the_evidence_tab(tmp_path):
    from nandatown.sim.runner import run_lab

    run_lab("voting", str(tmp_path))

    async def go():
        app = TownApp(out_dir=str(tmp_path))
        async with app.run_test() as pilot:
            app.query_one(TabbedContent).active = "tab-evidence"
            await pilot.pause()
            bundles = app.query_one("#bundle-table", DataTable)
            assert bundles.row_count == 1
            await pilot.click("#ev-verify")
            await pilot.pause()

    run_async(go())


def test_kiosk_mode_disables_execution_surfaces(tmp_path):
    async def go():
        app = TownApp(out_dir=str(tmp_path), kiosk=True)
        async with app.run_test() as pilot:
            assert not app.query("#agent-cmd")
            assert not app.query("#agent-go")
            assert not app.query("#svc-path")
            assert app.query("#run-go")
            assert app.query("#pr-go")
            await pilot.pause()

    run_async(go())


def test_kiosk_track_run_forces_mock_model(tmp_path, monkeypatch):
    import nandatown.runner as runner_module

    captured = {}

    def fake_run_town(*args, **kwargs):
        captured.update(kwargs)
        return "unused-bundle", object()

    monkeypatch.setenv("TOWN_MODEL", "hosted:paid")
    monkeypatch.setenv("TOWN_MODEL_KEY", "paid-secret")
    monkeypatch.delenv("NANDATOWN_KIOSK_ALLOW_HOSTED_MODEL", raising=False)
    monkeypatch.setattr(runner_module, "run_town", fake_run_town)
    monkeypatch.setattr(TownApp, "_show_result",
                        lambda self, bundle, result, log: None)

    async def go():
        app = TownApp(out_dir=str(tmp_path), kiosk=True)
        async with app.run_test() as pilot:
            app._run_target("quote-clean", None)
            await app.workers.wait_for_complete()
            await pilot.pause()

    run_async(go())
    assert captured["model"] == "mock:v1"


def test_kiosk_hosted_model_requires_operator_opt_in(tmp_path, monkeypatch):
    import nandatown.runner as runner_module

    captured = {}

    def fake_run_town(*args, **kwargs):
        captured.update(kwargs)
        return "unused-bundle", object()

    monkeypatch.setenv("TOWN_MODEL", "hosted:paid")
    monkeypatch.setenv("NANDATOWN_KIOSK_ALLOW_HOSTED_MODEL", "1")
    monkeypatch.setattr(runner_module, "run_town", fake_run_town)
    monkeypatch.setattr(TownApp, "_show_result",
                        lambda self, bundle, result, log: None)

    async def go():
        app = TownApp(out_dir=str(tmp_path), kiosk=True)
        async with app.run_test() as pilot:
            app._run_target("quote-clean", None)
            await app.workers.wait_for_complete()
            await pilot.pause()

    run_async(go())
    assert captured.get("model") is None
