package org.unibl.etf.phishtector.exception;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@ToString
public class SyntaxException extends HttpException {

  public SyntaxException() {
    super(HttpStatus.NOT_FOUND, null);
  }

  public SyntaxException(Object data) {
    super(HttpStatus.NOT_FOUND, data);
  }
}
