package org.unibl.etf.phishtector.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SPFRequest {

  private  String ipAddress;
  private  String mailFrom;
  private  String hostName;
}
