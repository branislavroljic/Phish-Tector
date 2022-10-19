package org.unibl.etf.phishtector.response.googleSafeBrowsing;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.unibl.etf.phishtector.request.ThreatEntry;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GoogleSafeBrowsingResponse {

  private String threatType;
  private String platformType;
  private ThreatEntry threat;
}
