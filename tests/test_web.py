from password_security_tool.web import create_app


def test_security_headers_present_on_responses():
    app = create_app()
    with app.test_client() as client:
        for path in ["/login", "/static/style.css", "/this-page-does-not-exist"]:
            response = client.get(path)
            assert response.headers["X-Frame-Options"] == "DENY"
            assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
