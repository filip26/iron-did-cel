package com.apicatalog.cel;

public class CelException extends Exception {

    private static final long serialVersionUID = 5229773071184534409L;

    public enum ErrorCode {
        BROKEN_CHAIN,
        UNSUPPORTED_ID,
        LOG_NOT_FOUND,
        RESOLUTION_FAILED,
    }

    private ErrorCode code;
    
    public CelException(ErrorCode code) {
        super(code.toString());
        this.code = code;
    }
    
    public ErrorCode getCode() {
        return code;
    }    
}
