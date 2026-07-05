

import java.security.SignatureException;

@FunctionalInterface
public interface AsymetricSigner {

    /**
     * 
     * @param data to be signed
     * @return the signature
     * @throws SignatureException
     */
    byte[] sign(byte[] data) throws SignatureException;

}
