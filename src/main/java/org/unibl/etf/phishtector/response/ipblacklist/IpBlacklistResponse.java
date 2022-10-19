package org.unibl.etf.phishtector.response.ipblacklist;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class IpBlacklistResponse {
  private boolean blacklisted;
}
