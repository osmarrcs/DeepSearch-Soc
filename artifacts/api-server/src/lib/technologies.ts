export interface Technology {
  id: string;
  name: string;
  category: string;
}

// Prefira nomes de produtos reais. Termos amplos como "Network Devices" ou
// "Cloud Platforms" geram resultados ruidosos e chamadas lentas na NVD.
export const TECHNOLOGIES: Technology[] = [
  // Infraestrutura e Segurança
  { id: "fortigate", name: "FortiGate", category: "Infraestrutura e Segurança" },
  { id: "fortimanager", name: "FortiManager", category: "Infraestrutura e Segurança" },
  { id: "fortianalyzer", name: "FortiAnalyzer", category: "Infraestrutura e Segurança" },
  { id: "forticlient-ems", name: "FortiClient EMS", category: "Infraestrutura e Segurança" },
  { id: "cisco-secure-email", name: "Cisco Secure Email", category: "Infraestrutura e Segurança" },
  { id: "senhasegura-pam", name: "senhasegura PAM", category: "Infraestrutura e Segurança" },
  { id: "f5-bigip", name: "F5 BIG-IP", category: "Infraestrutura e Segurança" },
  { id: "aws", name: "AWS", category: "Infraestrutura e Segurança" },
  { id: "openshift", name: "OpenShift", category: "Infraestrutura e Segurança" },
  { id: "vmware", name: "VMware", category: "Infraestrutura e Segurança" },
  { id: "kaspersky", name: "Kaspersky", category: "Infraestrutura e Segurança" },
  { id: "mcafee", name: "McAfee", category: "Infraestrutura e Segurança" },
  { id: "trellix", name: "Trellix", category: "Infraestrutura e Segurança" },
  { id: "openvpn", name: "OpenVPN", category: "Infraestrutura e Segurança" },
  { id: "zabbix", name: "Zabbix", category: "Infraestrutura e Segurança" },
  { id: "pulse-secure", name: "Pulse Secure", category: "Infraestrutura e Segurança" },

  // Sistemas e Produção
  { id: "windows", name: "Windows", category: "Sistemas e Produção" },
  { id: "linux-kernel", name: "Linux Kernel", category: "Sistemas e Produção" },
  { id: "kubernetes", name: "Kubernetes", category: "Sistemas e Produção" },
  { id: "docker", name: "Docker", category: "Sistemas e Produção" },
  { id: "ansible", name: "Ansible", category: "Sistemas e Produção" },
  { id: "git", name: "Git", category: "Sistemas e Produção" },
  { id: "cicd-tools", name: "CI/CD Tools", category: "Sistemas e Produção" },

  // Banco de Dados
  { id: "oracle", name: "Oracle", category: "Banco de Dados" },
  { id: "postgresql", name: "PostgreSQL", category: "Banco de Dados" },
  { id: "mysql", name: "MySQL", category: "Banco de Dados" },
  { id: "sql-server", name: "Microsoft SQL Server", category: "Banco de Dados" },
  { id: "mongodb", name: "MongoDB", category: "Banco de Dados" },
  { id: "redis", name: "Redis", category: "Banco de Dados" },
  { id: "firebird", name: "Firebird", category: "Banco de Dados" },
  { id: "interbase", name: "InterBase", category: "Banco de Dados" },

  // Navegadores
  { id: "google-chrome", name: "Google Chrome", category: "Navegadores" },
  { id: "mozilla-firefox", name: "Mozilla Firefox", category: "Navegadores" },
  { id: "microsoft-edge", name: "Microsoft Edge", category: "Navegadores" },
  { id: "safari", name: "Safari", category: "Navegadores" },
  { id: "brave", name: "Brave", category: "Navegadores" },
  { id: "opera", name: "Opera", category: "Navegadores" },

  // Aplicações e Desenvolvimento
  { id: "7zip", name: "7-Zip", category: "Aplicações e Desenvolvimento" },
  { id: "winrar", name: "WinRAR", category: "Aplicações e Desenvolvimento" },
  { id: "winzip", name: "WinZip", category: "Aplicações e Desenvolvimento" },
  { id: "obs-studio", name: "OBS Studio", category: "Aplicações e Desenvolvimento" },
  { id: "vscode", name: "Visual Studio Code", category: "Aplicações e Desenvolvimento" },
  { id: "jetbrains", name: "JetBrains IDEs", category: "Aplicações e Desenvolvimento" },
  { id: "python", name: "Python", category: "Aplicações e Desenvolvimento" },
  { id: "java", name: "Java", category: "Aplicações e Desenvolvimento" },
  { id: "nodejs", name: "Node.js", category: "Aplicações e Desenvolvimento" },
  { id: "microsoft-office", name: "Microsoft Office", category: "Aplicações e Desenvolvimento" },
  { id: "libreoffice", name: "LibreOffice", category: "Aplicações e Desenvolvimento" },
  { id: "adobe-acrobat", name: "Adobe Acrobat", category: "Aplicações e Desenvolvimento" },
  { id: "adobe-photoshop", name: "Adobe Photoshop", category: "Aplicações e Desenvolvimento" },
  { id: "autocad", name: "AutoCAD", category: "Aplicações e Desenvolvimento" },
  { id: "cribl-stream", name: "Cribl Stream", category: "Aplicações e Desenvolvimento" },
];
