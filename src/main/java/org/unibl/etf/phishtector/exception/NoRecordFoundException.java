package org.unibl.etf.phishtector.exception;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@ToString
public class NoRecordFoundException extends HttpException {

  public NoRecordFoundException() {
    super(HttpStatus.NOT_FOUND, null);
  }

  public NoRecordFoundException(Object data) {
    super(HttpStatus.NOT_FOUND, data);
  }
}
