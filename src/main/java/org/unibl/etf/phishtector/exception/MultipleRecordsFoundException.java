package org.unibl.etf.phishtector.exception;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@ToString
public class MultipleRecordsFoundException extends HttpException {

  public MultipleRecordsFoundException() {
    super(HttpStatus.NOT_FOUND, null);
  }

  public MultipleRecordsFoundException(Object data) {
    super(HttpStatus.NOT_FOUND, data);
  }
}
