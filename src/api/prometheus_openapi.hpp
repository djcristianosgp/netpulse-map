#pragma once

#include <string>

namespace netpulse {

struct ApiDependencies;

std::string escapePrometheusLabelValue(const std::string& val);
std::string formatPrometheusMetrics(const ApiDependencies& deps);
std::string buildOpenApiV1SpecJson(const std::string& version);

} // namespace netpulse
