package com.apicatalog.cel;

public class CelException extends Exception {

    private static final long serialVersionUID = 5229773071184534409L;

    public enum ErrorCode {
        UNSUPPORTED_ID,
        BROKEN_CHAIN,
        CORRUPTED_CHAIN,
        LOG_NOT_FOUND,
        RESOLUTION_FAILED,
        ABANDONED,
        INVALID_OPERATION,
        NO_SERVICE_ENDPOINTS,
        EVENT_TIME_GAP,
        DEACTIVATED,
//        MISSING_HEARTBEAT_PROPERTY,
        NO_EVENT_ENTRIES,
//        INVALID_DOCUMENT_ID, 
        INVALID_DID_DOCUMENT,
        MISSING_EVENT_PROOF,
        INVALID_EVENT_PROOF_PURPOSE,
        INVALID_EVENT_PROOF_CONTROLLER,
        ILLEGAL_ASSERTION_METHOD, 
        MISSING_WITNESS
    }

    private ErrorCode code;

    public CelException(ErrorCode code) {
        super(code.toString());
        this.code = code;
    }

    public CelException(ErrorCode code, String message) {
        super(code.toString() + "[" + message + "]");
        this.code = code;
    }

    public ErrorCode getCode() {
        return code;
    }
}
