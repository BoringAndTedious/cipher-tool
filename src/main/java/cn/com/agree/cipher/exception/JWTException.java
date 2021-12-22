package cn.com.agree.cipher.exception;

public class JWTException extends RuntimeException {
	public JWTException(String msg) {
		super(msg);
	}

	public JWTException(String msg, Throwable throwable) {
		super(msg, throwable);
	}
}
