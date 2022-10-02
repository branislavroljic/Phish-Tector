package org.unibl.etf.phishtector.response;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.unibl.etf.phishtector.model.Hop;
import org.unibl.etf.phishtector.response.dkim.DKIMVerificationResponse;
import org.unibl.etf.phishtector.response.dmarc.DMARCVerificationResponse;
import org.unibl.etf.phishtector.response.spf.SPFVerificationResponse;
import org.unibl.etf.phishtector.response.url.URLResponse;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MailAnalysisResponse {

  private List<Hop> hops;
  private DMARCVerificationResponse dmarcVerificationResponse;
  private SPFVerificationResponse spfVerificationResponse;
  private DKIMVerificationResponse dkimVerificationResponse;
  private URLResponse urlResponse;
}
