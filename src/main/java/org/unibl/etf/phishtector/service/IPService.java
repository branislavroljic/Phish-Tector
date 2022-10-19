package org.unibl.etf.phishtector.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.unibl.etf.phishtector.config.ApiProperties;
import org.unibl.etf.phishtector.model.Hop;
import org.unibl.etf.phishtector.request.IpBlacklistRequest;
import org.unibl.etf.phishtector.response.ipblacklist.IpBlacklistResponse;
import org.unibl.etf.phishtector.response.techniknews.IpAnalysisResponse;

@Service
@RequiredArgsConstructor
public class IPService {

  private static final String RECEIVED_IP_ADDRESS_REGEX = "(?<=\\[)\\d+(?:\\.\\d+){3}(?=\\])";
  private static final Pattern receivedIpAddressPattern =
      Pattern.compile(RECEIVED_IP_ADDRESS_REGEX);

  private final ApiProperties apiProperties;
  private final RestTemplate restTemplate;

  private String parseIpAddress(Hop hop) {

    if (hop.getFrom() != null) {
      Matcher matcher = receivedIpAddressPattern.matcher(hop.getFrom());
      if (matcher.find()) {
        return matcher.group(0);
      }
    }
    return null;
  }

  public IpAnalysisResponse investigateIPAddress(Hop hop) {
    String ipAddress = parseIpAddress(hop);
    return restTemplate.getForEntity(apiProperties.getTechniknews() + ipAddress,
        IpAnalysisResponse.class).getBody();
  }

  public IpBlacklistResponse checkBlacklistForIPAddress(Hop hop) {
    String ipAddress = parseIpAddress(hop);
    IpBlacklistRequest request =
        IpBlacklistRequest.builder().apikey(apiProperties.getIpblacklistKey()).ip(ipAddress)
            .build();
    return restTemplate.postForEntity(apiProperties.getIpblacklist(), request,
        IpBlacklistResponse.class).getBody();
  }


}
