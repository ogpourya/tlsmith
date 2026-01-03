async def intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    # This file is used by test.sh to verify modification capabilities
    
    # Example 1: Add a custom header
    headers['X-TLSmith'] = 'Intercepted'
    
    # Example 2: Modify Date (CRITICAL for test.sh validation)
    headers['Date'] = "Sat, 01 Jan 2099 00:00:00 GMT"
    
    return body, headers, status
