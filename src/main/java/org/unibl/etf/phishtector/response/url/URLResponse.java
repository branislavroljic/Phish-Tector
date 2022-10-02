package org.unibl.etf.phishtector.response.url;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.unibl.etf.phishtector.response.googleSafeBrowsing.GoogleSafeBrowsingResponse;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class URLResponse {

  private List<String> validUrls;
  private List<GoogleSafeBrowsingResponse> blacklistedUrls;
  private String exceptionMessage;
}
