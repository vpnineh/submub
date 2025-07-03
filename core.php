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
            // تبدیل به hysteria2://
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

    file_put_contents("$outputDir/{$type}.txt", implode("\n\n", $out));
    echo "Saved $type configs (" . count($out) . " items)\n";
}

$content = file_get_contents($inputFile);
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

// مرحله اول: استخراج URI-based
foreach ($regexPatterns as $type => $pattern) {
    preg_match_all($pattern, $content, $matches);
    if (!empty($matches[0])) {
        $configs[$type] = array_merge($configs[$type], $matches[0]);
    }
}

// استخراج YAML hysteria2
preg_match_all('/(?s)listen:\s*.*?(?=(\n{2,}|\Z))/', $content, $yamlBlocks);
foreach ($yamlBlocks[0] as $block) {
    if (strpos($block, 'tls:') !== false || strpos($block, 'obfs:') !== false) {
        $configs['hysteria2'][] = trim($block);
    }
}

// wireguard
preg_match_all('/(?s)\[Interface\].*?(?=(\n\[Peer\]|\Z))/', $content, $wgBlocks);
foreach ($wgBlocks[0] as $block) {
    if (strpos($block, 'PrivateKey') !== false) {
        $configs['wireguard'][] = trim($block);
    }
}

// خروجی هر نوع کانفیگ در فایل مجزا + ساخت mix.txt
$mix = [];
foreach ($configs as $type => $list) {
    if (!empty($list)) {
        saveConfigsWithFlags(array_unique($list), $type, $outputDir, $mix);
    }
}

file_put_contents($mixFile, implode("\n\n", $mix));
echo "Saved all configs to $mixFile\n";
