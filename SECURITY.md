Política de Segurança | Vanguards Visual Studio
Este documento detalha os protocolos de segurança e os procedimentos para reporte de vulnerabilidades nos sistemas desenvolvidos por Guilherme Silva (Kovaliosky DeV). Como uma operação focada em Cybersecurity, tratamos a integridade do código como nossa prioridade máxima.

0x01. Versões Suportadas
Apenas as versões mais recentes dos nossos sistemas ativos (como o portal principal, jogos e ferramentas de automação) recebem atualizações de segurança. Recomendamos manter seu ambiente sempre sincronizado com a branch main.

Versão	Suportada	Notas
v2.x	✅ Sim	Versão atual em produção.
v1.x	❌ Não	Descontinuada (End of Life).
0x02. Como Reportar uma Vulnerabilidade
Não utilize Issues públicas do GitHub para reportar falhas de segurança. Isso expõe nossos usuários e clientes a riscos desnecessários.

Se você encontrar uma falha (SQLi, XSS, quebra de autenticação ou exposição de dados), siga este protocolo:

Envio Seguro: Envie um e-mail detalhado para o setor de segurança da Vanguards Visual através do formulário de contato no portal oficial: visualstudioandsecurity.com.br.

Conteúdo do Reporte:

Descrição técnica da vulnerabilidade.

Passos para reprodução (PoC - Proof of Concept).

Impacto potencial no sistema.

0x03. Nossa Resposta (SLA)
Após o recebimento do reporte, nossa equipe técnica seguirá o seguinte fluxo:

Reconhecimento: Confirmaremos o recebimento em até 48 horas úteis.

Triagem: Avaliaremos a gravidade da falha e o impacto na infraestrutura.

Correção: Trabalharemos em um "hotfix" ou patch de segurança. Manteremos você informado durante todo o processo.

Divulgação: Uma vez corrigida a falha, poderemos publicar um aviso técnico se houver necessidade de transparência para a comunidade.

0x04. Diretrizes de Pesquisa Ética
Agradecemos a colaboração de pesquisadores de segurança, desde que:

Não causem interrupção dos nossos serviços (DoS/DDoS).

Não tentem acessar ou modificar dados de terceiros.

Pratiquem a Divulgação Responsável, aguardando a correção antes de tornar a falha pública.

Kovaliosky DeV
Senior Developer & Cybersecurity Specialist
