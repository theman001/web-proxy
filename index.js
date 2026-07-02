const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

app.use('/', createProxyMiddleware({
    target: 'https://claude.ai',
    changeOrigin: true,
    ws: true, // 클로드의 실시간 채팅 답변(WebSockets) 지원을 위해 추가
    cookieDomainRewrite: "", // 로그인 세션 쿠키가 현재 도메인에서 작동하도록 재작성
    onProxyRes: function (proxyRes, req, res) {
        // CORS 문제 방지를 위해 응답 헤더 추가
        proxyRes.headers['Access-Control-Allow-Origin'] = '*';
    }
}));

// 컨테이너 내부 포트는 3000을 유지합니다.
app.listen(3000, () => {
    console.log('Proxy server is running on http://localhost:3000');
});
