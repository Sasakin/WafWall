package com.waf.alert.controller;

import com.waf.alert.service.AlertService;
import com.waf.alert.service.BlocklistService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;

@Controller
public class DashboardController {

    private final AlertService alertService;
    private final BlocklistService blocklistService;

    public DashboardController(AlertService alertService, BlocklistService blocklistService) {
        this.alertService = alertService;
        this.blocklistService = blocklistService;
    }

    @GetMapping("/")
    public String index() {
        return "redirect:/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        Map<String, Object> stats = new HashMap<>();
        stats.put("blocklistSize", blocklistService.getBlocklistSize());
        stats.put("alertStats", alertService.getAlertStats());
        model.addAttribute("stats", stats);
        return "dashboard";
    }
}