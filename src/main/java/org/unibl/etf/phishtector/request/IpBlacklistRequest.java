package org.unibl.etf.phishtector.request;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class IpBlacklistRequest {

  private String apikey;
  private String ip;
}
