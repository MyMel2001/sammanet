# Sandbox Rendering Test

This page exercises the sandboxed <snet-script> blocks and sanitized <snet-style> blocks.

<snet-script>
console.log('sandbox test run');
document.body.innerHTML = '<b>oops</b>';
console.log('sandbox test end');
</snet-script>

<snet-script>
const a = 42;
console.log('second script runs with a=', a);
</snet-script>

<snet-style>
/* Test CSS injection into the final HTML */
h1 { color: #1e90ff; font-family: Arial, sans-serif; }
</snet-style>

This paragraph should render as normal content.

[Home](home.md)