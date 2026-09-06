def test_worker_module_imports():
    from app.importers.worker import ImportWorker
    assert ImportWorker is not None
