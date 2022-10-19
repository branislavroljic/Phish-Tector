package org.unibl.etf.phishtector.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.unibl.etf.phishtector.response.MailAnalysisResponse;
import org.unibl.etf.phishtector.service.MailService;

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

}
