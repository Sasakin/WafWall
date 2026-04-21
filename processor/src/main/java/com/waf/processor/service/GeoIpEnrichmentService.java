package com.waf.processor.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class GeoIpEnrichmentService {

    private static final Map<String, CountryInfo> GEO_DATABASE = new HashMap<>();

    @PostConstruct
    public void init() {
        loadDefaultGeoData();
    }

    public String getCountryCode(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "XX";
        }

        if (ip.startsWith("127.") || ip.startsWith("192.168.") ||
            ip.startsWith("10.") || ip.startsWith("172.16.")) {
            return "XX";
        }

        String firstOctet = ip.split("\\.")[0];
        return GEO_DATABASE.getOrDefault(firstOctet, new CountryInfo("XX", "Unknown")).countryCode;
    }

    public String getCountryName(String ip) {
        String countryCode = getCountryCode(ip);
        return GEO_DATABASE.values().stream()
            .filter(c -> c.countryCode.equals(countryCode))
            .map(c -> c.countryName)
            .findFirst()
            .orElse("Unknown");
    }

    public String getAsn(String ip) {
        return "AS" + Math.abs(ip.hashCode() % 65000);
    }

    public boolean isDatacenterIp(String ip) {
        String firstOctet = ip.split("\\.")[0];
        int first = Integer.parseInt(firstOctet);
        return first >= 64 && first <= 95;
    }

    public IpReputation getReputation(String ip) {
        return new IpReputation(
            getCountryCode(ip),
            isDatacenterIp(ip),
            false,
            getAsn(ip)
        );
    }

    private void loadDefaultGeoData() {
        String[][] data = {
            {"1", "US", "United States"},
            {"2", "EU", "Europe"},
            {"3", "AP", "Asia Pacific"},
            {"5", "EU", "Europe"},
            {"8", "US", "United States"},
            {"14", "AU", "Australia"},
            {"23", "US", "United States"},
            {"31", "EU", "Europe"},
            {"37", "EU", "Europe"},
            {"41", "AF", "Africa"},
            {"42", "AP", "Asia Pacific"},
            {"43", "JP", "Japan"},
            {"46", "EU", "Europe"},
            {"47", "CA", "Canada"},
            {"48", "US", "United States"},
            {"49", "JP", "Japan"},
            {"51", "GB", "United Kingdom"},
            {"52", "US", "United States"},
            {"53", "EU", "Europe"},
            {"54", "US", "United States"},
            {"58", "AU", "Australia"},
            {"59", "KR", "South Korea"},
            {"60", "JP", "Japan"},
            {"61", "AU", "Australia"},
            {"62", "EU", "Europe"},
            {"64", "US", "United States"},
            {"65", "US", "United States"},
            {"66", "US", "United States"},
            {"67", "US", "United States"},
            {"68", "US", "United States"},
            {"69", "US", "United States"},
            {"70", "US", "United States"},
            {"71", "US", "United States"},
            {"72", "US", "United States"},
            {"74", "US", "United States"},
            {"75", "US", "United States"},
            {"76", "US", "United States"},
            {"77", "US", "United States"},
            {"78", "US", "United States"},
            {"79", "US", "United States"},
            {"80", "EU", "Europe"},
            {"81", "EU", "Europe"},
            {"82", "EU", "Europe"},
            {"83", "EU", "Europe"},
            {"84", "EU", "Europe"},
            {"85", "EU", "Europe"},
            {"86", "EU", "Europe"},
            {"87", "EU", "Europe"},
            {"88", "EU", "Europe"},
            {"89", "EU", "Europe"},
            {"90", "EU", "Europe"},
            {"91", "EU", "Europe"},
            {"92", "EU", "Europe"},
            {"93", "EU", "Europe"},
            {"94", "EU", "Europe"},
            {"95", "EU", "Europe"},
            {"96", "US", "United States"},
            {"97", "US", "United States"},
            {"98", "US", "United States"},
            {"99", "US", "United States"},
            {"100", "US", "United States"},
            {"101", "US", "United States"},
            {"102", "US", "United States"},
            {"103", "US", "United States"},
            {"104", "US", "United States"},
            {"105", "US", "United States"},
            {"106", "US", "United States"},
            {"107", "US", "United States"},
            {"108", "US", "United States"},
            {"109", "US", "United States"},
            {"110", "US", "United States"},
            {"111", "US", "United States"},
            {"112", "US", "United States"},
            {"113", "US", "United States"},
            {"114", "US", "United States"},
            {"115", "US", "United States"},
            {"116", "US", "United States"},
            {"117", "US", "United States"},
            {"118", "US", "United States"},
            {"119", "US", "United States"},
            {"120", "US", "United States"},
            {"121", "US", "United States"},
            {"122", "US", "United States"},
            {"123", "US", "United States"},
            {"124", "US", "United States"},
            {"125", "US", "United States"},
            {"126", "US", "United States"},
            {"127", "US", "United States"},
            {"128", "US", "United States"},
            {"129", "US", "United States"},
            {"130", "US", "United States"},
            {"131", "US", "United States"},
            {"132", "US", "United States"},
            {"133", "US", "United States"},
            {"134", "US", "United States"},
            {"135", "US", "United States"},
            {"136", "US", "United States"},
            {"137", "US", "United States"},
            {"138", "US", "United States"},
            {"139", "US", "United States"},
            {"140", "US", "United States"},
            {"141", "US", "United States"},
            {"142", "US", "United States"},
            {"143", "US", "United States"},
            {"144", "US", "United States"},
            {"145", "US", "United States"},
            {"146", "US", "United States"},
            {"147", "US", "United States"},
            {"148", "US", "United States"},
            {"149", "US", "United States"},
            {"150", "US", "United States"},
            {"151", "US", "United States"},
            {"152", "US", "United States"},
            {"153", "US", "United States"},
            {"154", "US", "United States"},
            {"155", "US", "United States"},
            {"156", "US", "United States"},
            {"157", "US", "United States"},
            {"158", "US", "United States"},
            {"159", "US", "United States"},
            {"160", "US", "United States"},
            {"161", "US", "United States"},
            {"162", "US", "United States"},
            {"163", "US", "United States"},
            {"164", "US", "United States"},
            {"165", "US", "United States"},
            {"166", "US", "United States"},
            {"167", "US", "United States"},
            {"168", "US", "United States"},
            {"169", "US", "United States"},
            {"170", "US", "United States"},
            {"171", "US", "United States"},
            {"172", "US", "United States"},
            {"173", "US", "United States"},
            {"174", "US", "United States"},
            {"175", "US", "United States"},
            {"176", "US", "United States"},
            {"177", "US", "United States"},
            {"178", "US", "United States"},
            {"179", "US", "United States"},
            {"180", "US", "United States"},
            {"181", "US", "United States"},
            {"182", "US", "United States"},
            {"183", "US", "United States"},
            {"184", "US", "United States"},
            {"185", "US", "United States"},
            {"186", "US", "United States"},
            {"187", "US", "United States"},
            {"188", "US", "United States"},
            {"189", "US", "United States"},
            {"190", "US", "United States"},
            {"191", "US", "United States"},
            {"192", "US", "United States"},
            {"193", "US", "United States"},
            {"194", "US", "United States"},
            {"195", "US", "United States"},
            {"196", "US", "United States"},
            {"197", "US", "United States"},
            {"198", "US", "United States"},
            {"199", "US", "United States"},
            {"200", "BR", "Brazil"},
        };

        for (String[] row : data) {
            GEO_DATABASE.put(row[0], new CountryInfo(row[1], row[2]));
        }
    }

    private static class CountryInfo {
        final String countryCode;
        final String countryName;

        CountryInfo(String countryCode, String countryName) {
            this.countryCode = countryCode;
            this.countryName = countryName;
        }
    }

    public static class IpReputation {
        private final String countryCode;
        private final boolean isDatacenter;
        private final boolean isVpn;
        private final String asn;

        public IpReputation(String countryCode, boolean isDatacenter, boolean isVpn, String asn) {
            this.countryCode = countryCode;
            this.isDatacenter = isDatacenter;
            this.isVpn = isVpn;
            this.asn = asn;
        }

        public String getCountryCode() { return countryCode; }
        public boolean isDatacenter() { return isDatacenter; }
        public boolean isVpn() { return isVpn; }
        public String getAsn() { return asn; }
    }
}