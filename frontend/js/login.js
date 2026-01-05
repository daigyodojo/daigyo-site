document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const email = document.getElementById('email').value;
    const senha = document.getElementById('senha').value;
    const mensagem = document.getElementById('mensagem');

    const resposta = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, senha })
    });

    const dados = await resposta.json();

    if (!dados.sucesso) {
        mensagem.textContent = dados.mensagem;
        return;
    }

    // redireciona conforme perfil
    if (dados.tipo === 'admin') {
        window.location.href = '/admin.html';
    } else {
        window.location.href = '/aluno.html';
    }
});