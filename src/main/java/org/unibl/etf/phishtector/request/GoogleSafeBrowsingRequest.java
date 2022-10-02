package org.unibl.etf.phishtector.request;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GoogleSafeBrowsingRequest {
 private ThreatInfo threatInfo;
}
