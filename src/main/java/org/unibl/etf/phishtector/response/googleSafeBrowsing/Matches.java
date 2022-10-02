package org.unibl.etf.phishtector.response.googleSafeBrowsing;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Matches {

  private List<GoogleSafeBrowsingResponse> matches;
}
