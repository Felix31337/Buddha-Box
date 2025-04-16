// ==UserScript==
// @name         GreasyFork Script Finder
// @namespace    http://tampermonkey.net/
// @version      0.2
// @description  获取当前页面的主域名并打开 GreasyFork 查找脚本
// @author       Felix
// @license      Felix
// @match        *://*/*
// @grant        GM_registerMenuCommand
// @grant        GM_openInTab
// @updateURL    https://raw.githubusercontent.com/Qiulock/Scripts/refs/heads/main/ScriptFinder.js
// @downloadURL  https://raw.githubusercontent.com/Qiulock/Scripts/refs/heads/main/ScriptFinder.js
// ==/UserScript==
 
(function() {
    'use strict';
 
    // 注册菜单命令
    GM_registerMenuCommand("查找该域名的GreasyFork脚本", function() {
        // 获取当前页面的完整域名
        const domain = window.location.hostname;
 
        // 使用正则表达式提取主域名
        const mainDomain = domain.replace(/^.*\.(?:com|org|net|gov|edu|io|co|info|me|tv)(?:\.[a-z]{2,})?$/, "$&").split('.').slice(-2).join('.');
 
        // 生成 GreasyFork 搜索链接
        const url = `https://greasyfork.org/zh-CN/scripts/by-site/${mainDomain}`;
 
        // 在新标签页中打开该链接
        GM_openInTab(url, { active: true });
    });
})();
