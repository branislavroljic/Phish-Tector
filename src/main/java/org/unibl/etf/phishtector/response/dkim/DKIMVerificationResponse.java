package org.unibl.etf.phishtector.response.dkim;

import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DKIMVerificationResponse {

  private List<DKIMSignatureRecordResponse> signatureRecords;
  private List<DKIMFailExceptionResponse> exceptionResponses;
  private String exceptionMessage;
}
