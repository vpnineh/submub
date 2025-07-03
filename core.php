<?php
ini_set("display_errors", 1);
error_reporting(E_ALL);

$inputFile = 'sub.conf';
$outputDir = 'sub';
$mixFile = $outputDir . '/mix.txt';

if (!file_exists($outputDir)) {
    mkdir($outputDir, 0777, true);
}

function countryFlag($countryCode) {
    $code = strtoupper($countryCode);
    return $code ? implode('', array_map(
        fn($c) => mb_convert_encoding('&#' . (127397 + ord($c)) . ';', 'UTF-8', 'HTML-ENTITIES'),
        str_split($code)
    )) : '';
}

function getCountryFromConfig($config) {
    preg_match('/(vless|vmess|trojan|ss|hy2|hysteria|tuic):\/\/([^@]+)/', $config, $match);
    if (!$match) return '';
    $host = explode(':', explode('@', $match[2])[1] ?? $match[2])[0];
    return getCountryByHost($host);
}

function getCountryFromYaml($yaml) {
    preg_match('/server:\s*([^\s]+)/', $yaml, $match);
    if (!$match) preg_match('/endpoint:\s*([^\s:]+)/', $yaml, $match);
    $host = $match[1] ?? '';
    return getCountryByHost($host);
}

function getCountryByHost($host) {
    $url = "http://ip-api.com/json/$host?fields=countryCode";
    $json = @file_get_contents($url);
    $data = json_decode($json, true);
    return $data['countryCode'] ?? '';
}

function saveConfigsWithFlags($configs, $type, $outputDir, &$allMix) {
    $out = [];
    foreach ($configs as $cfg) {
        if (str_starts_with(trim($cfg), 'listen:')) {
            $encoded = base64_encode($cfg);
            $uri = "hysteria2://$encoded";
            $country = getCountryFromYaml($cfg);
            $flag = countryFlag($country);
            $out[] = $uri . " # $flag";
            $allMix[] = $uri . " # $flag";
        } elseif (str_starts_with(trim($cfg), '[Interface]')) {
            $country = getCountryFromYaml($cfg);
            $flag = countryFlag($country);
            $out[] = trim($cfg) . " # $flag";
            $allMix[] = trim($cfg) . " # $flag";
        } else {
            $country = getCountryFromConfig($cfg);
            $flag = countryFlag($country);
            $out[] = trim($cfg) . " # $flag";
            $allMix[] = trim($cfg) . " # $flag";
        }
    }

    $filePath = "$outputDir/{$type}.txt";
    if (!file_exists($filePath)) {
        touch($filePath);
    }
    file_put_contents($filePath, implode("\n\n", $out));
    echo "✅ Saved $type configs (" . count($out) . " items) to $filePath\n";
}

// --- خواندن فایل و پردازش لینک‌ها + کانفیگ‌ها ---
$content = file_get_contents($inputFile);
$lines = explode("\n", $content);
$finalContent = '';

// بررسی هر خط (سابسکریپشن یا کانفیگ مستقیم)
foreach ($lines as $line) {
    $line = trim($line);
    if (!$line) continue;

    if (filter_var($line, FILTER_VALIDATE_URL)) {
        echo "🔁 Fetching subscription: $line\n";
        $raw = @file_get_contents($line);
        if ($raw) {
            $decoded = base64_decode(trim($raw));
            if ($decoded) {
                $finalContent .= "\n" . $decoded;
            }
        }
    } else {
        $finalContent .= "\n" . $line;
    }
}

// حالا `finalContent` شامل همه کانفیگ‌هاست
$configs = [
    'vmess'     => [],
    'vless'     => [],
    'trojan'    => [],
    'ss'        => [],
    'hysteria'  => [],
    'hysteria2' => [],
    'hy2'       => [],
    'tuic'      => [],
    'wireguard' => [],
];

$regexPatterns = [
    'vmess'     => '/vmess:\/\/[a-zA-Z0-9+\/=._\-]+/',
    'vless'     => '/vless:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
    'trojan'    => '/trojan:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
    'ss'        => '/ss:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
    'tuic'      => '/tuic:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
    'hysteria'  => '/hysteria:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
    'hy2'       => '/hy2:\/\/[a-zA-Z0-9@:%._+~#=\/?\-&]+/',
];

foreach ($regexPatterns as $type => $pattern) {
    preg_match_all($pattern, $finalContent, $matches);
    if (!empty($matches[0])) {
        $configs[$type] = array_merge($configs[$type], $matches[0]);
    }
}

// hysteria2 YAML-based
preg_match_all('/(?s)listen:\s*.*?(?=(\n{2,}|\Z))/', $finalContent, $yamlBlocks);
foreach ($yamlBlocks[0] as $block) {
    if (strpos($block, 'tls:') !== false || strpos($block, 'obfs:') !== false) {
        $configs['hysteria2'][] = trim($block);
    }
}

// wireguard
preg_match_all('/(?s)\[Interface\].*?(?=(\n\[Peer\]|\Z))/', $finalContent, $wgBlocks);
foreach ($wgBlocks[0] as $block) {
    if (strpos($block, 'PrivateKey') !== false) {
        $configs['wireguard'][] = trim($block);
    }
}

// ذخیره خروجی‌ها
$mix = [];
foreach ($configs as $type => $list) {
    if (!empty($list)) {
        saveConfigsWithFlags(array_unique($list), $type, $outputDir, $mix);
    }
}

if (!file_exists($mixFile)) {
    touch($mixFile);
}
file_put_contents($mixFile, implode("\n\n", $mix));
echo "✅ All configs saved to $mixFile\n";
