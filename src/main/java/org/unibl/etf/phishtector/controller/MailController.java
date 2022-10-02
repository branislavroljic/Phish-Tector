package org.unibl.etf.phishtector.controller;

import de.malkusch.whoisServerList.publicSuffixList.PublicSuffixList;
import de.malkusch.whoisServerList.publicSuffixList.PublicSuffixListFactory;
import java.io.IOException;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.concurrent.ExecutionException;
import javax.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.apache.james.mime4j.MimeException;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.unibl.etf.phishtector.response.MailAnalysisResponse;
import org.unibl.etf.phishtector.service.MailService;
import org.xbill.DNS.TextParseException;

@RestController
@RequestMapping("/api/mail")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:4200")
public class MailController {

  private final MailService mailService;

  @PostMapping
  public ResponseEntity<MailAnalysisResponse> analyzeMail(
      @RequestParam("mailFile") MultipartFile mailFile)
      throws Exception {

    return ResponseEntity.ok(mailService.analyzeMail(mailFile));
  }

  @GetMapping("/psl")
  public void psl() {
    PublicSuffixListFactory factory = new PublicSuffixListFactory();
    PublicSuffixList suffixList = factory.build();
    System.out.println(suffixList.getRegistrableDomain("www.google.com"));
    System.out.println(suffixList.getRegistrableDomain("nesto.dva.example.co.us"));
    System.out.println(suffixList.getRegistrableDomain("google.com"));
  }

//  @GetMapping
//  public void getRecords()
//      throws UnknownHostException, ExecutionException, InterruptedException, TextParseException {
//      mailService.getRecords();
//  }
}
