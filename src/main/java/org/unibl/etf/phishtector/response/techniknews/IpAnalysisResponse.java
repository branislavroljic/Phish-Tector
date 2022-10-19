package org.unibl.etf.phishtector.response.techniknews;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class IpAnalysisResponse {
  private String status;
  private String continent;
  private String country;
  private String countryCode;
  private String regionName;
  private String city;
  private String zip;
  private double lat;
  private double lon;
  private String timezone;
  private String currency;
  private String isp;
  private String org;
  private String as;
  private String reverse;
  private boolean mobile;
  private boolean proxy;
  private String ip;
}
