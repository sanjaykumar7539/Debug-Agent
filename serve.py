"""Start a single local API worker using the supported defaults."""
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:create_app", factory=True, host="127.0.0.1", port=8000,
                workers=1, access_log=False, limit_concurrency=20,
                timeout_keep_alive=5)
