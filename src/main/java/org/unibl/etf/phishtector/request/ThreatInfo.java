package org.unibl.etf.phishtector.request;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class ThreatInfo {
  private List<String> threatTypes;
  private List<String> platformTypes;
  private List<String> threatEntryTypes;
  private List<ThreatEntry> threatEntries;
}
