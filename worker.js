let DoH = "dns.google"; // 推荐改用支持完整扩展且对ECS更友好的上游，如dns.google或dns.alidns.com
let DoH路径 = 'dns-query';

export default {
  async fetch(request, env) {
    if (env.DOH) {
      DoH = env.DOH;
      const match = DoH.match(/:\/\/([^\/]+)/);
      if (match) DoH = match[1];
    }
    DoH路径 = env.PATH || env.TOKEN || DoH路径;
    if (DoH路径.includes("/")) DoH路径 = DoH路径.split("/")[1];

    // 在 env.DOH 覆盖之后重新计算，确保使用最终的 DoH 值
    const dnsDoH = `https://${DoH}/dns-query`;
    const jsonDoH = `https://${DoH}/resolve`;

    const url = new URL(request.url);
    const path = url.pathname;
    const hostname = url.hostname;

    // 处理 OPTIONS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // 如果请求路径匹配，则作为 DoH 服务器处理
    if (path === `/${DoH路径}`) {
      return await DOHRequest(request, dnsDoH, jsonDoH);
    }

    // IP地理位置信息查询代理
    if (path === '/ip-info') {
      return await handleIpInfo(request, env, url);
    }

    // 核心：处理带高级 ECS 功能的 DNS 解析请求
    if (url.searchParams.has("doh")) {
      const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
      let doh = url.searchParams.get("doh") || dnsDoH;
      if (doh.includes(url.host)) doh = jsonDoH; // 避免自循环

      // 提取客户端传递的 ecs 参数，若无则尝试自适应
      let clientEcs = url.searchParams.get("ecs") || request.headers.get('CF-Connecting-IP');

      try {
        // 执行具备 CNAME 递归、自适应掩码、NS防污染的高级查询
        const combinedResult = await advancedDnsResolver(doh, domain, clientEcs);
        return new Response(JSON.stringify(combinedResult, null, 2), {
          headers: { 
            "content-type": "application/json; charset=UTF-8",
            'Access-Control-Allow-Origin': '*'
          }
        });
      } catch (err) {
        console.error("高级 DNS 查询失败:", err);
        return new Response(JSON.stringify({
          error: `高级 DNS 查询失败: ${err.message}`,
          doh: doh,
          domain: domain,
          stack: err.stack
        }, null, 2), {
          headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' },
          status: 500
        });
      }
    }

    if (env.URL302) return Response.redirect(env.URL302, 302);
    else if (env.URL) {
      if (env.URL.toString().toLowerCase() == 'nginx') {
        return new Response(await nginx(), { headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
      } else return await 代理URL(env.URL, url);
    } else return await HTML();
  }
};

/**
 * 高级智能 DNS 解析器
 * 核心特性：IPv6 ECS 自适应掩码、CNAME 递归追踪、NS 查询防污染不带 ECS
 */
 async function advancedDnsResolver(doh, domain, clientIp) {
   let ecsParam = "";
   if (clientIp) {
     const isIPv6 = clientIp.includes(":");
     if (isIPv6) {
       let cleanIPv6 = clientIp.split('%')[0].trim();
       let mask = 64; // 默认自适应 /64 掩码
       if (cleanIPv6.startsWith("240e") || cleanIPv6.startsWith("2408")) mask = 56; // 针对电信/联通精细化
       
       // 调用工具函数清空主机位
       ecsParam = anonymizeIPv6(cleanIPv6, mask);
     } else {
       ecsParam = anonymizeIPv4(clientIp);
     }
   }
 
   // 并行请求：注意把 ecsParam 传入
   const ipv4Promise = queryDnsWithEcs(doh, domain, "A", ecsParam);
   const ipv6Promise = queryDnsWithEcs(doh, domain, "AAAA", ecsParam);
   const nsPromise = queryDnsWithEcs(doh, domain, "NS", ""); // NS 链路保持绝对干净
 
   const [ipv4Result, ipv6Result, nsResult] = await Promise.all([ipv4Promise, ipv6Promise, nsPromise]);
 
   // 组装最终结果
   let combinedResult = {
     Status: ipv4Result.Status ?? ipv6Result.Status ?? nsResult.Status ?? 0,
     TC: ipv4Result.TC || ipv6Result.TC || false,
     RD: ipv4Result.RD || ipv6Result.RD || false,
     RA: ipv4Result.RA || ipv6Result.RA || false,
     AD: ipv4Result.AD || ipv6Result.AD || false,
     CD: ipv4Result.CD || ipv6Result.CD || false,
     Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
     Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || [])],
     EDNS_CLIENT_SUBNET: ecsParam || "None", 
     ipv4: { records: ipv4Result.Answer || [] },
     ipv6: { records: ipv6Result.Answer || [] },
     ns: { records: [] }
   };
 
   // 递归处理 CNAME（同时查询 A 和 AAAA）
   const cnameRecords = combinedResult.Answer.filter(r => r.type === 5);
   if (cnameRecords.length > 0
     && combinedResult.ipv4.records.filter(r => r.type === 1).length === 0
     && combinedResult.ipv6.records.filter(r => r.type === 28).length === 0) {
     const targetDomain = cnameRecords[cnameRecords.length - 1].data;
     try {
       const [recursiveA, recursiveAAAA] = await Promise.all([
         queryDnsWithEcs(doh, targetDomain, "A", ecsParam),
         queryDnsWithEcs(doh, targetDomain, "AAAA", ecsParam)
       ]);
       if (recursiveA.Answer) {
         combinedResult.Answer.push(...recursiveA.Answer);
         combinedResult.ipv4.records.push(...recursiveA.Answer.filter(r => r.type === 1));
       }
       if (recursiveAAAA.Answer) {
         combinedResult.Answer.push(...recursiveAAAA.Answer);
         combinedResult.ipv6.records.push(...recursiveAAAA.Answer.filter(r => r.type === 28));
       }
     } catch (e) {
       console.error("CNAME 递归 ECS 失败:", e);
     }
   }
 
   // 整理 NS 记录
   const nsRecords = [];
   if (nsResult.Answer) nsRecords.push(...nsResult.Answer.filter(r => r.type === 2));
   if (nsResult.Authority) nsRecords.push(...nsResult.Authority.filter(r => r.type === 2 || r.type === 6));
   combinedResult.ns.records = nsRecords;
   combinedResult.Answer.push(...nsRecords);
 
   return combinedResult;
 }

/**
 * 底层 DNS över HTTPS 核心请求函数，支持 RFC 7871 传参
 */
async function queryDnsWithEcs(dohServer, domain, type, ednsSubnet) {
  const dohUrl = new URL(dohServer);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);
  
  // 注入标准的 RFC 7871 DoH JSON 参数
  if (ednsSubnet) {
    dohUrl.searchParams.set("edns_client_subnet", ednsSubnet);
  }

  const fetchOptions = [
    { headers: { 'Accept': 'application/dns-json', 'User-Agent': 'Cloudflare-ECS-Adaptive-Client' } },
    { headers: { 'Accept': 'application/json' } }
  ];

  let lastError = null;
  for (const options of fetchOptions) {
    try {
      const response = await fetch(dohUrl.toString(), options);
      if (response.ok) {
        const text = await response.text();
        return JSON.parse(text);
      }
      lastError = new Error(`上游错误状态码: ${response.status}`);
    } catch (err) {
      lastError = err;
    }
  }
  return { Status: 2, Comment: `解析异常: ${lastError?.message}`, Answer: [], Question: [{ name: domain, type: type }] };
}

// 处理单独的 IP info 接口
async function handleIpInfo(request, env, url) {
  if (env.TOKEN) {
    const token = url.searchParams.get('token');
    if (token != env.TOKEN) {
      return new Response(JSON.stringify({ status: "error", message: "Token不正确" }), { status: 403, headers: { "content-type": "application/json" } });
    }
  }
  const ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    const data = await response.json();
    data.timestamp = new Date().toISOString();
    return new Response(JSON.stringify(data, null, 4), { headers: { "content-type": "application/json; charset=UTF-8", 'Access-Control-Allow-Origin': '*' } });
  } catch (error) {
    return new Response(JSON.stringify({ status: "error", message: error.message }), { status: 500, headers: { 'Access-Control-Allow-Origin': '*' } });
  }
}

// 保持你原有的 DOHRequest 逻辑不变，作为代理回退通道
async function DOHRequest(request, dnsDoH, jsonDoH) {
  const { method, headers, body } = request;
  const UA = headers.get('User-Agent') || 'DoH Client';
  const url = new URL(request.url);
  const { searchParams } = url;
  try {
    if (method === 'GET' && !url.search) return new Response('Bad Request', { status: 400 });
    let response;
    if (method === 'GET' && searchParams.has('name')) {
      const searchDoH = searchParams.has('type') ? url.search : url.search + '&type=A';
      response = await fetch(dnsDoH + searchDoH, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
      if (!response.ok) response = await fetch(jsonDoH + searchDoH, { headers: { 'Accept': 'application/dns-json', 'User-Agent': UA } });
    } else if (method === 'GET') {
      response = await fetch(dnsDoH + url.search, { headers: { 'Accept': 'application/dns-message', 'User-Agent': UA } });
    } else if (method === 'POST') {
      response = await fetch(dnsDoH, { method: 'POST', headers: { 'Accept': 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': UA }, body: body });
    } else {
      return new Response('不支持的格式', { status: 400 });
    }
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    if (method === 'GET' && searchParams.has('name')) responseHeaders.set('Content-Type', 'application/json');
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Access-Control-Allow-Origin': '*' } });
  }
}
// IPv6 网络前缀提取器（严格符合 RFC 7871 规范，主机位置零）
function anonymizeIPv6(ip, mask) {
  // 补全 :: 缩写，使其还原为标准 8 段
  let parts;
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftParts = left ? left.split(':') : [];
    const rightParts = right ? right.split(':') : [];
    parts = [...leftParts, ...Array(8 - leftParts.length - rightParts.length).fill('0'), ...rightParts];
  } else {
    parts = ip.split(':');
  }
  parts = parts.map(p => p.padStart(4, '0'));
  
  if (mask === 64) {
    return parts.slice(0, 4).join(':') + '::/64';
  } else if (mask === 48) {
    return parts.slice(0, 3).join(':') + '::/48';
  } else if (mask === 56) {
    // 提取第 4 段的前两位 hex，后两位清零
    let seg4 = parts[3].substring(0, 2) + '00';
    return [...parts.slice(0, 3), seg4].join(':') + '::/56';
  }
  return ip + '/' + mask;
}

// IPv4 网络前缀提取器
function anonymizeIPv4(ip) {
  let parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return ip + '/24';
}

async function HTML() {
  // 否则返回 HTML 页面
  const html = `<!DOCTYPE html>
<html lang="zh-CN">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-over-HTTPS Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="icon"
    href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg"
    type="image/x-icon">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      min-height: 100vh;
      padding: 0;
      margin: 0;
      line-height: 1.6;
      background: url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),
        linear-gradient(135deg, rgba(253, 101, 60, 0.85) 0%, rgba(251,152,30, 0.85) 100%);
      background-size: cover;
      background-position: center center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      padding: 30px 20px;
      box-sizing: border-box;
    }

    .page-wrapper {
      width: 100%;
      max-width: 800px;
      margin: 0 auto;
    }

    .container {
      width: 100%;
      max-width: 800px;
      margin: 20px auto;
      background-color: rgba(255, 255, 255, 0.65);
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
      padding: 30px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.4);
    }

    h1 {
      /* 创建文字渐变效果 */
      background-image: linear-gradient(to right, rgb(249, 171, 76), rgb(252, 103, 60));
      /* 回退颜色，用于不支持渐变文本的浏览器 */
      color: rgb(252, 103, 60);
      -webkit-background-clip: text;
      -moz-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      -moz-text-fill-color: transparent;
      
      font-weight: 600;
      /* 注意：渐变文本和阴影效果同时使用可能不兼容，暂时移除阴影 */
      text-shadow: none;
    }

    .card {
      margin-bottom: 20px;
      border: none;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
      background-color: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(5px);
      -webkit-backdrop-filter: blur(5px);
    }

    .card-header {
      background-color: rgba(255, 242, 235, 0.9);
      font-weight: 600;
      padding: 12px 20px;
      border-bottom: none;
    }

    .form-label {
      font-weight: 500;
      margin-bottom: 8px;
      color: rgb(70, 50, 40);
    }

    .form-select,
    .form-control {
      border-radius: 6px;
      padding: 10px;
      border: 1px solid rgba(253, 101, 60, 0.3);
      background-color: rgba(255, 255, 255, 0.9);
    }

    .btn-primary {
      background-color: rgb(253, 101, 60);
      border: none;
      border-radius: 6px;
      padding: 10px 20px;
      font-weight: 500;
      transition: all 0.2s ease;
    }

    .btn-primary:hover {
      background-color: rgb(230, 90, 50);
      transform: translateY(-1px);
    }

    pre {
      background-color: rgba(255, 245, 240, 0.9);
      padding: 15px;
      border-radius: 6px;
      border: 1px solid rgba(253, 101, 60, 0.2);
      white-space: pre-wrap;
      word-break: break-all;
      font-family: Consolas, Monaco, 'Andale Mono', monospace;
      font-size: 14px;
      max-height: 400px;
      overflow: auto;
    }

    .loading {
      display: none;
      text-align: center;
      padding: 20px 0;
    }

    .loading-spinner {
      border: 4px solid rgba(0, 0, 0, 0.1);
      border-left: 4px solid rgb(253, 101, 60);
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      margin: 0 auto 10px;
    }

    .badge {
      margin-left: 5px;
      font-size: 11px;
      vertical-align: middle;
    }

    @keyframes spin {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }

    .footer {
      margin-top: 30px;
      text-align: center;
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
    }

    .beian-info {
      text-align: center;
      font-size: 13px;
    }

    .beian-info a {
      color: var(--primary-color);
      text-decoration: none;
      border-bottom: 1px dashed var(--primary-color);
      padding-bottom: 2px;
    }

    .beian-info a:hover {
      border-bottom-style: solid;
    }

    @media (max-width: 576px) {
      .container {
        padding: 20px;
      }

      .github-corner:hover .octo-arm {
        animation: none;
      }

      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
    }

    .error-message {
      color: #e63e00;
      margin-top: 10px;
    }

    .success-message {
      color: #e67e22;
    }

    .nav-tabs .nav-link {
      border-top-left-radius: 6px;
      border-top-right-radius: 6px;
      padding: 8px 16px;
      font-weight: 500;
      color: rgb(150, 80, 50);
    }

    .nav-tabs .nav-link.active {
      background-color: rgba(255, 245, 240, 0.8);
      border-bottom-color: rgba(255, 245, 240, 0.8);
      color: rgb(253, 101, 60);
    }

    .tab-content {
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 0 0 6px 6px;
      padding: 15px;
      border: 1px solid rgba(253, 101, 60, 0.2);
      border-top: none;
    }

    .ip-record {
      padding: 5px 10px;
      margin-bottom: 5px;
      border-radius: 4px;
      background-color: rgba(255, 255, 255, 0.9);
      border: 1px solid rgba(253, 101, 60, 0.15);
    }

    .ip-record:hover {
      background-color: rgba(255, 235, 225, 0.9);
    }

    .ip-address {
      font-family: monospace;
      font-weight: 600;
      min-width: 130px;
      color: rgb(80, 60, 50);
      cursor: pointer;
      position: relative;
      transition: color 0.2s ease;
      display: inline-block;
    }

    .ip-address:hover {
      color: rgb(253, 101, 60);
    }

    .ip-address:after {
      content: '';
      position: absolute;
      left: 100%;  /* 从IP地址的右侧开始定位 */
      top: 0;
      opacity: 0;
      white-space: nowrap;
      font-size: 12px;
      color: rgb(253, 101, 60);
      transition: opacity 0.3s ease;
      font-family: 'Segoe UI', sans-serif;
      font-weight: normal;
    }

    .ip-address.copied:after {
      content: '✓ 已复制';
      opacity: 1;
    }

    .result-summary {
      margin-bottom: 15px;
      padding: 10px;
      background-color: rgba(255, 235, 225, 0.8);
      border-radius: 6px;
    }

    .result-tabs {
      margin-bottom: 20px;
    }

    .geo-info {
      margin: 0 10px;
      font-size: 0.85em;
      flex-grow: 1;
      text-align: center;
    }

    .geo-country {
      color: rgb(230, 90, 50);
      font-weight: 500;
      padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 4px;
      display: inline-block;
    }

    .geo-as {
      color: rgb(253, 101, 60);
      padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 4px;
      margin-left: 5px;
      display: inline-block;
    }

    .geo-blocked {
      color: #ffffff;
      background-color: #dc3545;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
      display: inline-block;
      animation: pulse-red 2s infinite;
    }

    @keyframes pulse-red {
      0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); }
      70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); }
      100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); }
    }

    .geo-loading {
      color: rgb(150, 100, 80);
      font-style: italic;
    }

    .ttl-info {
      min-width: 80px;
      text-align: right;
      color: rgb(180, 90, 60);
    }

    .copy-link {
      color: rgb(253, 101, 60);
      text-decoration: none;
      border-bottom: 1px dashed rgb(253, 101, 60);
      padding-bottom: 2px;
      cursor: pointer;
      position: relative;
    }

    .copy-link:hover {
      border-bottom-style: solid;
    }

    .copy-link:after {
      content: '';
      position: absolute;
      top: 0;
      right: -65px;
      opacity: 0;
      white-space: nowrap;
      color: rgb(253, 101, 60);
      font-size: 12px;
      transition: opacity 0.3s ease;
    }

    .copy-link.copied:after {
      content: '✓ 已复制';
      opacity: 1;
    }

    .github-corner svg {
      fill: rgb(255, 255, 255);
      color: rgb(251,152,30);
      position: absolute;
      top: 0;
      right: 0;
      border: 0;
      width: 80px;
      height: 80px;
    }

    .github-corner:hover .octo-arm {
      animation: octocat-wave 560ms ease-in-out;
    }

    /* 添加章鱼猫挥手动画关键帧 */
    @keyframes octocat-wave {
      0%, 100% { transform: rotate(0); }
      20%, 60% { transform: rotate(-25deg); }
      40%, 80% { transform: rotate(10deg); }
    }

    @media (max-width: 576px) {
      .container {
        padding: 20px;
      }

      .github-corner:hover .octo-arm {
        animation: none;
      }

      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
    }
  </style>
</head>

<body>
  <a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path
        d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
        fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path
        d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
        fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://sm2.doh.pub/dns-query">https://sm2.doh.pub/dns-query (腾讯)</option>
              <option value="https://doh.360.cn/resolve">https://doh.360.cn/resolve (360)</option>
              <option value="https://cloudflare-dns.com/dns-query">https://cloudflare-dns.com/dns-query (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.sb/dns-query">https://dns.sb/dns-query (DNS.SB)</option>
              <option value="https://zero.dns0.eu/">https://zero.dns0.eu (dns0.eu)</option>
              <option value="https://dns.nextdns.io">	https://dns.nextdns.io (NextDNS)</option>
              <option value="https://dns.rabbitdns.org/dns-query">https://dns.rabbitdns.org/dns-query (Rabbit DNS)</option>
              <option value="https://basic.rethinkdns.com/">https://basic.rethinkdns.com (RethinkDNS)</option>
              <option value="https://v.recipes/dns-query">https://v.recipes/dns-query (v.recipes DNS)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/dns-query">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="www.google.com"
                placeholder="输入域名，如 example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary flex-grow-1">解析</button>
            <button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display: none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>

        <!-- 结果展示区，包含选项卡 -->
        <div id="resultContainer" style="display: none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button"
                role="tab">IPv4 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button"
                role="tab">IPv6 地址</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS
                记录</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button"
                role="tab">原始数据</button>
            </li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel" aria-labelledby="ipv4-tab">
              <div class="result-summary" id="ipv4Summary"></div>
              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>

        <!-- 错误信息区域 -->
        <div id="errorContainer" style="display: none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      <p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">https://<span
              id="currentDomain">...</span>/${DoH路径}</span></strong><br>基于 Cloudflare Workers 上游 ${DoH} 的 DoH (DNS over HTTPS)
        解析服务</p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // 获取当前页面的 URL 和主机名
    const currentUrl = window.location.href;
    const currentHost = window.location.host;
    const currentProtocol = window.location.protocol;
    const currentDohPath = '${DoH路径}';
    const currentDohUrl = currentProtocol + '//' + currentHost + '/' + currentDohPath;

    // 记录当前使用的 DoH 地址
    let activeDohUrl = currentDohUrl;

    // 阻断IP列表
    const 阻断IPv4 = [
      '104.21.16.1',
      '104.21.32.1',
      '104.21.48.1',
      '104.21.64.1',
      '104.21.80.1',
      '104.21.96.1',
      '104.21.112.1'
    ];

    const 阻断IPv6 = [
      '2606:4700:3030::6815:1001',
      '2606:4700:3030::6815:3001',
      '2606:4700:3030::6815:7001',
      '2606:4700:3030::6815:5001'
    ];

    // 检查IP是否在阻断列表中
    function isBlockedIP(ip) {
      return 阻断IPv4.includes(ip) || 阻断IPv6.includes(ip);
    }

    // 显示当前正在使用的 DoH 服务
    function updateActiveDohDisplay() {
      const dohSelect = document.getElementById('dohSelect');
      if (dohSelect.value === 'current') {
        activeDohUrl = currentDohUrl;
      }
    }

    // 初始更新
    updateActiveDohDisplay();

    // 当选择自定义时显示输入框
    document.getElementById('dohSelect').addEventListener('change', function () {
      const customContainer = document.getElementById('customDohContainer');
      customContainer.style.display = (this.value === 'custom') ? 'block' : 'none';

      if (this.value === 'current') {
        activeDohUrl = currentDohUrl;
      } else if (this.value !== 'custom') {
        activeDohUrl = this.value;
      }
    });

    // 清除按钮功能
    document.getElementById('clearBtn').addEventListener('click', function () {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });

    // 复制结果功能
    document.getElementById('copyBtn').addEventListener('click', function () {
      const resultText = document.getElementById('result').textContent;
      navigator.clipboard.writeText(resultText).then(function () {
        const originalText = this.textContent;
        this.textContent = '已复制';
        setTimeout(() => {
          this.textContent = originalText;
        }, 2000);
      }.bind(this)).catch(function (err) {
        console.error('无法复制文本: ', err);
      });
    });

    // 格式化 TTL
    function formatTTL(seconds) {
      if (seconds < 60) return seconds + '秒';
      if (seconds < 3600) return Math.floor(seconds / 60) + '分钟';
      if (seconds < 86400) return Math.floor(seconds / 3600) + '小时';
      return Math.floor(seconds / 86400) + '天';
    }

    // 查询 IP 地理位置信息 - 使用我们自己的代理API而非直接访问HTTP地址
    async function queryIpGeoInfo(ip) {
      try {
        // 改为使用我们自己的代理接口
        const response = await fetch(\`./ip-info?ip=\${ip}&token=${DoH路径}\`);
            if (!response.ok) {
              throw new Error(\`HTTP 错误: \${response.status}\`);
            }
            return await response.json();
          } catch (error) {
            console.error('IP 地理位置查询失败:', error);
            return null;
          }
        }
        
        // 处理点击复制功能
        function handleCopyClick(element, textToCopy) {
          navigator.clipboard.writeText(textToCopy).then(function() {
            // 添加复制成功的反馈
            element.classList.add('copied');
            
            // 2秒后移除复制成功效果
            setTimeout(() => {
              element.classList.remove('copied');
            }, 2000);
          }).catch(function(err) {
            console.error('复制失败:', err);
          });
        }
        
        // 显示记录
        function displayRecords(data) {
          document.getElementById('resultContainer').style.display = 'block';
          document.getElementById('errorContainer').style.display = 'none';
          document.getElementById('result').textContent = JSON.stringify(data, null, 2);
          
          // IPv4 记录
          const ipv4Records = data.ipv4?.records || [];
          const ipv4Container = document.getElementById('ipv4Records');
          ipv4Container.innerHTML = '';
          
          if (ipv4Records.length === 0) {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>未找到 IPv4 记录</strong>\`;
          } else {
            document.getElementById('ipv4Summary').innerHTML = \`<strong>找到 \${ipv4Records.length} 条 IPv4 记录</strong>\`;
            
            ipv4Records.forEach(record => {
              const recordDiv = document.createElement('div');
              recordDiv.className = 'ip-record';
              
              if (record.type === 5) { // CNAME 记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-success">CNAME</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 1) {  // A记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="geo-info geo-loading">正在获取位置信息...</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv4Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                // 添加地理位置信息
                const geoInfoSpan = recordDiv.querySelector('.geo-info');
                
                // 检查是否为阻断IP
                if (isBlockedIP(record.data)) {
                  // 异步查询 IP 地理位置信息获取AS信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    // 显示阻断IP标识（替代国家信息）
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    // 如果有AS信息，正常显示
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    // 查询失败时仍显示阻断IP标识
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  // 异步查询 IP 地理位置信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      // 更新为实际的地理位置信息
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      // 添加国家信息
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';
                    
                      let locationText = geoData.country || '未知国家';
                      if (geoData.regionName) {
                        locationText += geoData.regionName;
                      }

                      countrySpan.textContent = locationText;
                      geoInfoSpan.appendChild(countrySpan);
                      
                      // 添加 AS 信息
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as || '未知 AS';
                      geoInfoSpan.appendChild(asSpan);
                    } else {
                      // 查询失败或无结果
                      geoInfoSpan.textContent = '位置信息获取失败';
                    }
                  });
                }
              }
            });
          }
          
          // IPv6 记录
          const ipv6Records = data.ipv6?.records || [];
          const ipv6Container = document.getElementById('ipv6Records');
          ipv6Container.innerHTML = '';
          
          if (ipv6Records.length === 0) {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>未找到 IPv6 记录</strong>\`;
          } else {
            document.getElementById('ipv6Summary').innerHTML = \`<strong>找到 \${ipv6Records.length} 条 IPv6 记录</strong>\`;
            
            ipv6Records.forEach(record => {
              const recordDiv = document.createElement('div');
              recordDiv.className = 'ip-record';
              
              if (record.type === 5) { // CNAME 记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-success">CNAME</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 28) {  // AAAA记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="geo-info geo-loading">正在获取位置信息...</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                ipv6Container.appendChild(recordDiv);
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
                // 添加地理位置信息
                const geoInfoSpan = recordDiv.querySelector('.geo-info');
                
                // 检查是否为阻断IP
                if (isBlockedIP(record.data)) {
                  // 异步查询 IP 地理位置信息获取AS信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    // 显示阻断IP标识（替代国家信息）
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                    
                    // 如果有AS信息，正常显示
                    if (geoData && geoData.status === 'success' && geoData.as) {
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as;
                      geoInfoSpan.appendChild(asSpan);
                    }
                  }).catch(() => {
                    // 查询失败时仍显示阻断IP标识
                    geoInfoSpan.innerHTML = '';
                    geoInfoSpan.classList.remove('geo-loading');
                    
                    const blockedSpan = document.createElement('span');
                    blockedSpan.className = 'geo-blocked';
                    blockedSpan.textContent = '阻断IP';
                    geoInfoSpan.appendChild(blockedSpan);
                  });
                } else {
                  // 异步查询 IP 地理位置信息
                  queryIpGeoInfo(record.data).then(geoData => {
                    if (geoData && geoData.status === 'success') {
                      // 更新为实际的地理位置信息
                      geoInfoSpan.innerHTML = '';
                      geoInfoSpan.classList.remove('geo-loading');
                      
                      // 添加国家信息
                      const countrySpan = document.createElement('span');
                      countrySpan.className = 'geo-country';

                      let locationText = geoData.country || '未知国家';
                      if (geoData.regionName) {
                        locationText += geoData.regionName;
                      }

                      countrySpan.textContent = locationText;

                      geoInfoSpan.appendChild(countrySpan);
                      
                      // 添加 AS 信息
                      const asSpan = document.createElement('span');
                      asSpan.className = 'geo-as';
                      asSpan.textContent = geoData.as || '未知 AS';
                      geoInfoSpan.appendChild(asSpan);
                    } else {
                      // 查询失败或无结果
                      geoInfoSpan.textContent = '位置信息获取失败';
                    }
                  });
                }
              }
            });
          }
          
          // NS 记录
          const nsRecords = data.ns?.records || [];
          const nsContainer = document.getElementById('nsRecords');
          nsContainer.innerHTML = '';
          
          if (nsRecords.length === 0) {
            document.getElementById('nsSummary').innerHTML = \`<strong>未找到 NS 记录</strong>\`;
          } else {
            document.getElementById('nsSummary').innerHTML = \`<strong>找到 \${nsRecords.length} 条名称服务器记录</strong>\`;
            
            nsRecords.forEach(record => {
              const recordDiv = document.createElement('div');
              recordDiv.className = 'ip-record';
              
              // 不同类型的记录使用不同的显示方式
              if (record.type === 2) {  // NS 记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-info">NS</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
                
              } else if (record.type === 6) {  // SOA 记录
                // SOA 记录格式: primary_ns admin_email serial refresh retry expire minimum
                const soaParts = record.data.split(' ');
                let adminEmail = soaParts[1].replace('.', '@');
                if (adminEmail.endsWith('.')) adminEmail = adminEmail.slice(0, -1);
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="ip-address" data-copy="\${record.name}">\${record.name}</span>
                    <span class="badge bg-warning">SOA</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                  <div class="ps-3 small">
                    <div><strong>主 NS:</strong> <span class="ip-address" data-copy="\${soaParts[0]}">\${soaParts[0]}</span></div>
                    <div><strong>管理邮箱:</strong> <span class="ip-address" data-copy="\${adminEmail}">\${adminEmail}</span></div>
                    <div><strong>序列号:</strong> \${soaParts[2]}</div>
                    <div><strong>刷新间隔:</strong> \${formatTTL(soaParts[3])}</div>
                    <div><strong>重试间隔:</strong> \${formatTTL(soaParts[4])}</div>
                    <div><strong>过期时间:</strong> \${formatTTL(soaParts[5])}</div>
                    <div><strong>最小 TTL:</strong> \${formatTTL(soaParts[6])}</div>
                  </div>
                \`;
                
                // 添加点击事件，为SOA记录中的所有可点击元素添加事件
                const copyElems = recordDiv.querySelectorAll('.ip-address');
                copyElems.forEach(elem => {
                  elem.addEventListener('click', function() {
                    handleCopyClick(this, this.getAttribute('data-copy'));
                  });
                });
                
              } else {
                // 其他类型的记录
                recordDiv.innerHTML = \`
                  <div class="d-flex justify-content-between align-items-center">
                    <span class="ip-address" data-copy="\${record.data}">\${record.data}</span>
                    <span class="badge bg-secondary">类型: \${record.type}</span>
                    <span class="text-muted ttl-info">TTL: \${formatTTL(record.TTL)}</span>
                  </div>
                \`;
                
                // 添加点击事件
                const copyElem = recordDiv.querySelector('.ip-address');
                copyElem.addEventListener('click', function() {
                  handleCopyClick(this, this.getAttribute('data-copy'));
                });
              }
              
              nsContainer.appendChild(recordDiv);
            });
          }
          
          // 当用户切换到IPv4或IPv6选项卡时，确保显示已加载的地理位置信息
          document.getElementById('ipv4-tab').addEventListener('click', function() {
            // 如果还有加载中的地理位置信息，可以在这里处理
          });
          
          document.getElementById('ipv6-tab').addEventListener('click', function() {
            // 如果还有加载中的地理位置信息，可以在这里处理
          });
          
          // 显示复制按钮
          document.getElementById('copyBtn').style.display = 'block';
        }
        
        // 显示错误
        function displayError(message) {
          document.getElementById('resultContainer').style.display = 'none';
          document.getElementById('errorContainer').style.display = 'block';
          document.getElementById('errorMessage').textContent = message;
          document.getElementById('copyBtn').style.display = 'none';
        }
        
        // 表单提交后发起 DNS 查询请求
        document.getElementById('resolveForm').addEventListener('submit', async function(e) {
          e.preventDefault();
          const dohSelect = document.getElementById('dohSelect').value;
          let doh;
          
          if(dohSelect === 'current') {
            doh = currentDohUrl;
          } else if(dohSelect === 'custom') {
            doh = document.getElementById('customDoh').value;
            if (!doh) {
              alert('请输入自定义 DoH 地址');
              return;
            }
          } else {
            doh = dohSelect;
          }
          
          const domain = document.getElementById('domain').value;
          if (!domain) {
            alert('请输入需要解析的域名');
            return;
          }
          
          // 显示加载状态
          document.getElementById('loading').style.display = 'block';
          document.getElementById('resultContainer').style.display = 'none';
          document.getElementById('errorContainer').style.display = 'none';
          document.getElementById('copyBtn').style.display = 'none';
          
          try {
            // 发起查询，参数采用 GET 请求方式，type=all 表示同时查询 A 和 AAAA
            const response = await fetch(\`?doh=\${encodeURIComponent(doh)}&domain=\${encodeURIComponent(domain)}&type=all\`);
            
            if (!response.ok) {
              throw new Error(\`HTTP 错误: \${response.status}\`);
            }
            
            const json = await response.json();
            
            // 检查响应是否包含错误
            if (json.error) {
              displayError(json.error);
            } else {
              displayRecords(json);
            }
          } catch (error) {
            displayError('查询失败: ' + error.message);
          } finally {
            // 隐藏加载状态
            document.getElementById('loading').style.display = 'none';
          }
        });
        
        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', function() {
          // 使用本地存储记住最后使用的域名
          const lastDomain = localStorage.getItem('lastDomain');
          if (lastDomain) {
            document.getElementById('domain').value = lastDomain;
          }
          
          // 监听域名输入变化并保存
          document.getElementById('domain').addEventListener('input', function() {
            localStorage.setItem('lastDomain', this.value);
          });

          // 更新显示当前域名
          document.getElementById('currentDomain').textContent = currentHost;
          
          // 更新DoH下拉选择框的自动选项，显示完整URL
          const currentDohOption = document.getElementById('currentDohOption');
          if (currentDohOption) {
            currentDohOption.textContent = currentDohUrl + ' (当前站点)';
          }
          
          // 设置DoH链接复制功能
          const dohUrlDisplay = document.getElementById('dohUrlDisplay');
          if (dohUrlDisplay) {
            dohUrlDisplay.addEventListener('click', function() {
              const textToCopy = currentProtocol + '//' + currentHost + '/' + currentDohPath;
              navigator.clipboard.writeText(textToCopy).then(function() {
                dohUrlDisplay.classList.add('copied');
                setTimeout(() => {
                  dohUrlDisplay.classList.remove('copied');
                }, 2000);
              }).catch(function(err) {
                console.error('复制失败:', err);
              });
            });
          }

          // 添加Get Json按钮的点击事件
          document.getElementById('getJsonBtn').addEventListener('click', function() {
            const dohSelect = document.getElementById('dohSelect').value;
            let dohUrl;
            
            // 获取当前选择的DoH服务器URL
            if(dohSelect === 'current') {
              dohUrl = currentDohUrl;
            } else if(dohSelect === 'custom') {
              dohUrl = document.getElementById('customDoh').value;
              if (!dohUrl) {
                alert('请输入自定义 DoH 地址');
                return;
              }
            } else {
              dohUrl = dohSelect;
            }
            
            // 获取域名
            const domain = document.getElementById('domain').value;
            if (!domain) {
              alert('请输入需要解析的域名');
              return;
            }
            
            // 构建完整的查询URL
            let jsonUrl = new URL(dohUrl);
            // 使用name参数(标准DNS-JSON格式)
            jsonUrl.searchParams.set('name', domain);
            
            // 在新标签页打开
            window.open(jsonUrl.toString(), '_blank');
          });
        });
  </script>
</body>

</html>`;

  return new Response(html, {
    headers: { "content-type": "text/html;charset=UTF-8" }
  });
}

async function 代理URL(代理网址, 目标网址) {
  const 网址列表 = await 整理(代理网址);
  const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

  // 解析目标 URL
  const 解析后的网址 = new URL(完整网址);
  console.log(解析后的网址);
  // 提取并可能修改 URL 组件
  const 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
  const 主机名 = 解析后的网址.hostname;
  let 路径名 = 解析后的网址.pathname;
  const 查询参数 = 解析后的网址.search;

  // 处理路径名
  if (路径名.charAt(路径名.length - 1) == '/') {
    路径名 = 路径名.slice(0, -1);
  }
  路径名 += 目标网址.pathname;

  // 构建新的 URL
  const 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

  // 反向代理请求
  const 响应 = await fetch(新网址);

  // 创建新的响应
  let 新响应 = new Response(响应.body, {
    status: 响应.status,
    statusText: 响应.statusText,
    headers: 响应.headers
  });

  // 添加自定义头部，包含 URL 信息
  //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
  //新响应.headers.set('X-Original-URL', 完整网址);
  新响应.headers.set('X-New-URL', 新网址);

  return 新响应;
}

async function 整理(内容) {
  // 将制表符、双引号、单引号和换行符都替换为逗号
  // 然后将连续的多个逗号替换为单个逗号
  var 替换后的内容 = 内容.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');

  // 删除开头和结尾的逗号（如果有的话）
  if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
  if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

  // 使用逗号分割字符串，得到地址数组
  const 地址数组 = 替换后的内容.split(',');

  return 地址数组;
}

async function nginx() {
  const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
  return text;
}
