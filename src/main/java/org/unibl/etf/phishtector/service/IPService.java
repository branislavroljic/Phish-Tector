package org.unibl.etf.phishtector.service;

import java.util.regex.Matcher;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.unibl.etf.phishtector.config.ApiProperties;
import org.unibl.etf.phishtector.model.Hop;
import org.unibl.etf.phishtector.response.techniknews.IPAnalysisResponse;

@Service
@RequiredArgsConstructor
public class IPService {

  private static final String RECEIVED_IP_ADDRESS_REGEX = "(?<=\\[)\\d+(?:\\.\\d+){3}(?=\\])";
  private static final Pattern receivedIpAddressPattern =
      Pattern.compile(RECEIVED_IP_ADDRESS_REGEX);

  private final ApiProperties apiProperties;
  private final RestTemplate restTemplate;

//  public List<IPAnalysisResponse> investigateIPAddresses(List<Hop> hops) {
//    List<String> ipAddresses = parseIpAddresses(hops);
//    List<IPAnalysisResponse> responses = new ArrayList<>();
//    ipAddresses.forEach(ipAddress -> {
//      IPAnalysisResponse ipAnalysisResponse =
//          restTemplate.getForEntity(apiProperties.getTechniknews() + ipAddress,
//              IPAnalysisResponse.class).getBody();
//      responses.add(ipAnalysisResponse);
//    });
//
//    return responses;
//  }
//
//  private List<String> parseIpAddresses(List<Hop> hops) {
//    List<String> ipAddresses = new ArrayList<>();
//    new ArrayList<>();
//    hops.forEach(hop -> {
//      if (hop.getFrom() != null) {
//        Matcher matcher = receivedIpAddressPattern.matcher(hop.getFrom());
//        if (matcher.find()) {
//          ipAddresses.add(matcher.group(0));
//        }
//      }
//    });
//    return ipAddresses;
//  }

  private String parseIpAddress(Hop hop) {

    if (hop.getFrom() != null) {
      Matcher matcher = receivedIpAddressPattern.matcher(hop.getFrom());
      if (matcher.find()) {
        return matcher.group(0);
      }
    }
    return null;
  }

  public IPAnalysisResponse investigateIPAddress(Hop hop) {
    String ipAddress = parseIpAddress(hop);
    return restTemplate.getForEntity(apiProperties.getTechniknews() + ipAddress,
            IPAnalysisResponse.class).getBody();

  }


}
