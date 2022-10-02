package org.unibl.etf.phishtector.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SPFTag {
  private String qualifier;
  private String value;
}
