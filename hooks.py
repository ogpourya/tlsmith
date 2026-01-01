async def intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    # Example 1: Add a custom header
    headers['X-TLSmith'] = 'Intercepted'
    
    # Example 2: Modify Date (for testing)
    headers['Date'] = "Sat, 01 Jan 2099 00:00:00 GMT"
    
    return body, headers, status
