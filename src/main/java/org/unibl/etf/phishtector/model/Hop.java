package org.unibl.etf.phishtector.model;

import java.time.Duration;
import java.util.Date;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.unibl.etf.phishtector.response.techniknews.IPAnalysisResponse;

@Data
@NoArgsConstructor
public class Hop {
  private Duration delay;
  private String from;
  private String by;
  private String with;
  private Date dateTime;
  private IPAnalysisResponse ipAnalysisResponse;
}
