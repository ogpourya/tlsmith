# hooks.py - Example interception script

async def intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    """
    Hook to modify the upstream response before sending it to the client.
    
    Args:
        body: The raw response body bytes.
        headers: Dictionary of response headers.
        status: The HTTP status code.
        
    Returns:
        Tuple of (modified_body, modified_headers, modified_status)
    """

    # Example 1: Add a custom debugging header
    headers['X-Intercepted-By'] = 'TLSmith'
    
    # Example 2: Modify content (simple string replacement)
    # Be careful with encoding and compression!
    # TLSmith auto-decompresses upstream responses for you.
    try:
        # Check if it's likely text/html
        content_type = headers.get('Content-Type', '').lower()
        if 'text' in content_type or 'json' in content_type:
            text = body.decode('utf-8')
            if "Example" in text:
                text = text.replace("Example", "Pwnd")
                body = text.encode('utf-8')
    except Exception:
        pass # Skip binary or decoding errors

    # Example 3: Test Date header modification (used in test.sh)
    # headers['Date'] = "Sat, 01 Jan 2099 00:00:00 GMT"
    
    return body, headers, status
