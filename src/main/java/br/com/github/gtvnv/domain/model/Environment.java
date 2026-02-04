package br.com.github.gtvnv.domain.model;

import java.time.Instant;

public record Environment(String ipAddress, Instant timestamp, int riskScore) {}