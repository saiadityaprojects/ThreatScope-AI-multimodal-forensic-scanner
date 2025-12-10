import React, { useState, useEffect } from "react";
import { createRoot } from "react-dom/client";
import { GoogleGenAI, Type } from "@google/genai";
import { motion, AnimatePresence } from "framer-motion";
import { Gamepad2, XCircle, CheckCircle, AlertTriangle, Shield, Terminal, Globe, MapPin, Network, FileAudio, FileText } from "lucide-react";
import { Map, Marker } from "pigeon-maps";

// --- Types ---
type AnalysisResult = {
  verdict: "Clean" | "Suspicious" | "Malicious";
  confidence_score: number;
  simple_analysis: {
    explanation: string;
  };
  recommendations: {
    do: string[];
    dont: string[];
  };
  expert_analysis: {
    technical_summary: string;
    mitre_attack_ids: string[];
    spf_dkim_dmarc_status: string;
  };
  sender_metadata: {
    ip_address: string;
    estimated_country: string;
    is_vpn_or_proxy: boolean;
  };
  headers: {
    from: string;
    return_path: string;
    subject: string;
  };
  red_flags: string[];
  attacker_replication_code: string;
};

type QuizScenario = {
    is_phishing: boolean;
    sender: string;
    subject: string;
    body: string;
    clues: string;
};

// --- Gemini Configuration ---
const ai = new GoogleGenAI({ apiKey: import.meta.env.VITE_GEMINI_API_KEY });

const analysisSchema = {
  type: Type.OBJECT,
  properties: {
    verdict: {
      type: Type.STRING,
      enum: ["Clean", "Suspicious", "Malicious"],
      description: "The overall classification of the file.",
    },
    confidence_score: {
      type: Type.INTEGER,
      description: "Confidence level of the verdict from 0 to 100.",
    },
    simple_analysis: {
      type: Type.OBJECT,
      properties: {
        explanation: { 
            type: Type.STRING, 
            description: "A simple, non-technical explanation for a 10-year-old." 
        }
      }
    },
    recommendations: {
      type: Type.OBJECT,
      properties: {
        do: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
          description: "List of safe actions the user SHOULD take."
        },
        dont: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
          description: "List of dangerous actions the user SHOULD NOT take."
        }
      }
    },
    expert_analysis: {
      type: Type.OBJECT,
      properties: {
        technical_summary: { 
            type: Type.STRING, 
            description: "Technical details regarding obfuscation, header analysis, macros, or audio analysis." 
        },
        mitre_attack_ids: { 
            type: Type.ARRAY, 
            items: { type: Type.STRING },
            description: "Relevant MITRE ATT&CK Technique IDs."
        },
        spf_dkim_dmarc_status: {
            type: Type.STRING,
            description: "Analysis of authentication headers (SPF/DKIM/DMARC) or file metadata."
        }
      }
    },
    sender_metadata: {
        type: Type.OBJECT,
        properties: {
            ip_address: { type: Type.STRING, description: "The deepest originating IP address extracted from headers or metadata." },
            estimated_country: { type: Type.STRING, description: "Estimated country of origin." },
            is_vpn_or_proxy: { type: Type.BOOLEAN, description: "True if origin suggests anonymization." }
        }
    },
    headers: {
      type: Type.OBJECT,
      properties: {
        from: { type: Type.STRING },
        return_path: { type: Type.STRING },
        subject: { type: Type.STRING },
      },
    },
    red_flags: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "List of specific phishing indicators found.",
    },
    attacker_replication_code: {
        type: Type.STRING,
        description: "A safe, educational Python script snippet demonstrating the attack vector."
    }
  },
  required: ["verdict", "confidence_score", "simple_analysis", "recommendations", "expert_analysis", "sender_metadata", "headers", "red_flags", "attacker_replication_code"],
};

const quizSchema = {
    type: Type.OBJECT,
    properties: {
        is_phishing: { type: Type.BOOLEAN },
        sender: { type: Type.STRING },
        subject: { type: Type.STRING },
        body: { type: Type.STRING, description: "The plain text body of the email scenario." },
        clues: { type: Type.STRING, description: "A short explanation of why it is safe or phishing." }
    },
    required: ["is_phishing", "sender", "subject", "body", "clues"]
};

// --- Components ---

const Tooltip: React.FC<{ term?: string; definition: string; children: React.ReactNode; className?: string; position?: "top" | "right" }> = ({ term, definition, children, className, position = "top" }) => {
    const [isVisible, setIsVisible] = useState(false);
    
    const styles = position === "right" ? {
        container: "left-full top-1/2 -translate-y-1/2 ml-3",
        arrow: "left-[-4px] top-1/2 -translate-y-1/2 border-l border-b",
        initial: { opacity: 0, x: -10, scale: 0.95 },
        animate: { opacity: 1, x: 0, scale: 1 },
        exit: { opacity: 0, x: -10, scale: 0.95 }
    } : {
        container: "bottom-full left-1/2 -translate-x-1/2 mb-2",
        arrow: "bottom-[-4px] left-1/2 -translate-x-1/2 border-r border-b",
        initial: { opacity: 0, y: 5, scale: 0.95 },
        animate: { opacity: 1, y: 0, scale: 1 },
        exit: { opacity: 0, y: 5, scale: 0.95 }
    };

    return (
        <span 
            className={`relative inline-block group ${className || "border-b border-dashed border-white/30 cursor-help"}`}
            onMouseEnter={() => setIsVisible(true)}
            onMouseLeave={() => setIsVisible(false)}
        >
            {children}
            <AnimatePresence>
                {isVisible && (
                    <motion.div 
                        initial={styles.initial}
                        animate={styles.animate}
                        exit={styles.exit}
                        className={`absolute ${styles.container} w-56 p-4 bg-black/90 border border-white/20 rounded-xl text-xs text-white shadow-xl z-50 backdrop-blur-xl pointer-events-none text-center`}
                    >
                        {term && <div className="font-bold mb-1.5 text-blue-300 text-sm">{term}</div>}
                        <div className="leading-relaxed text-white/80">{definition}</div>
                        <div className={`absolute ${styles.arrow} w-2 h-2 bg-black/90 border-white/20 rotate-45`}></div>
                    </motion.div>
                )}
            </AnimatePresence>
        </span>
    );
};

const ThreatMap = ({ ip }: { ip: string }) => {
    const [geoData, setGeoData] = useState<any>(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (!ip || ip === "N/A" || ip === "127.0.0.1") return;

        const fetchGeo = async () => {
            setLoading(true);
            try {
                // Using ipapi.co (HTTPS supported)
                const res = await fetch(`https://ipapi.co/${ip}/json/`);
                if (!res.ok) throw new Error("Failed to fetch");
                const data = await res.json();
                if (data.latitude && data.longitude) {
                    setGeoData(data);
                }
            } catch (e) {
                console.error("Geo fetch failed", e);
            } finally {
                setLoading(false);
            }
        };
        fetchGeo();
    }, [ip]);

    // Default view if no IP or local
    const center: [number, number] = geoData ? [geoData.latitude, geoData.longitude] : [20, 0];
    const zoom = geoData ? 10 : 2;

    return (
        <div className="glass-panel rounded-3xl p-6 h-full flex flex-col relative overflow-hidden">
            <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2 font-mono uppercase text-white/50">
                <Globe size={16} className="text-cyan-400"/> Threat Origin
            </h3>
            
            <div className="flex-grow relative rounded-xl overflow-hidden border border-white/10 min-h-[200px]">
                <Map 
                    height={300} 
                    defaultCenter={center} 
                    defaultZoom={zoom}
                    center={center}
                    zoom={zoom}
                    provider={(x, y, z) => {
                        const s = String.fromCharCode(97 + (x + y + z) % 3)
                        return `https://${s}.basemaps.cartocdn.com/dark_all/${z}/${x}/${y}@2x.png`
                    }}
                >
                    {geoData && <Marker width={40} anchor={center} color="#ef4444" />}
                </Map>
                
                {/* Overlay Info */}
                <div className="absolute bottom-4 left-4 right-4 glass p-3 rounded-xl border border-white/10 flex justify-between items-center text-xs">
                    <div className="flex flex-col">
                        <span className="text-white/40 uppercase tracking-wider font-bold mb-1">ORIGIN IP</span>
                        <span className="font-mono text-cyan-300 font-bold flex items-center gap-2">
                            <Network size={12}/> {ip}
                        </span>
                    </div>
                    {geoData && (
                        <div className="text-right">
                            <span className="block font-bold text-white">{geoData.city}, {geoData.country_code}</span>
                            <span className="text-white/50">{geoData.org}</span>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

const Header = ({ onOpenQuiz }: { onOpenQuiz: () => void }) => (
  <motion.header 
    initial={{ y: -50, opacity: 0 }}
    animate={{ y: 0, opacity: 1 }}
    transition={{ duration: 0.6, type: "spring" }}
    className="flex justify-between items-center sticky top-4 z-40 mx-4 mt-4"
  >
    <div className="glass px-6 py-3 rounded-full flex items-center gap-3">
      <div className="w-8 h-8 bg-gradient-to-tr from-blue-400 to-purple-500 rounded-lg flex items-center justify-center shadow-lg">
        <span className="text-white text-lg font-bold">T</span>
      </div>
      <h1 className="text-xl font-bold tracking-tight text-white">
        ThreatScope <span className="text-white/40 font-light">AI</span>
      </h1>
    </div>
    <div className="flex items-center gap-3">
      <button 
        onClick={onOpenQuiz}
        className="glass px-6 py-3 rounded-full flex items-center gap-2 text-xs font-bold text-yellow-400 hover:bg-white/5 transition-colors"
      >
        <Gamepad2 size={16} /> TRAINING DOJO
      </button>
      
      <motion.div 
        className="glass px-6 py-3 rounded-full flex items-center gap-2 text-green-300 text-xs font-medium"
      >
        <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse"></span>
        API Connected
      </motion.div>
    </div>
  </motion.header>
);

const ModeToggle = ({ isAnalyst, toggle }: { isAnalyst: boolean; toggle: () => void }) => {
    return (
        <motion.div 
            layout 
            className="flex justify-center w-full mb-8 relative z-20"
        >
            <div className="bg-white/5 backdrop-blur-xl p-1.5 rounded-full border border-white/10 flex relative shadow-2xl w-80">
                <motion.div
                    className="absolute top-1.5 bottom-1.5 left-1.5 rounded-full bg-gradient-to-r from-blue-600 to-purple-600 shadow-lg z-0"
                    initial={false}
                    animate={{
                        x: isAnalyst ? "100%" : "0%",
                    }}
                    style={{ width: "calc(50% - 0.375rem)" }}
                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                />
                
                <button 
                    onClick={() => isAnalyst && toggle()}
                    className={`relative z-10 w-1/2 py-2 rounded-full text-sm font-bold transition-colors duration-300 ${!isAnalyst ? 'text-white' : 'text-white/50 hover:text-white'}`}
                >
                    Civilian Mode
                </button>
                <button 
                    onClick={() => !isAnalyst && toggle()}
                    className={`relative z-10 w-1/2 py-2 rounded-full text-sm font-bold transition-colors duration-300 ${isAnalyst ? 'text-white' : 'text-white/50 hover:text-white'}`}
                >
                    <Tooltip 
                        position="right"
                        term="Security Operations Center"
                        definition="For cybersecurity professionals. Reveals raw headers, IOCs, MITRE ATT&CK tags, and payload analysis."
                        className="border-none cursor-pointer w-full h-full flex items-center justify-center"
                    >
                        SOC Analyst
                    </Tooltip>
                </button>
            </div>
        </motion.div>
    );
};

const FileDropZone = ({
  onFileLoaded,
  fileLoadedName
}: {
  onFileLoaded: (content: string, name: string, mimeType: string) => void;
  fileLoadedName: string | null;
}) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => setIsDragging(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  };

  const processFile = (file: File) => {
    const isText = file.name.endsWith('.eml') || file.name.endsWith('.txt') || file.type === 'text/plain';
    const reader = new FileReader();
    
    reader.onload = (event) => {
      const result = event.target?.result as string;
      // Default to application/octet-stream if type is missing (common for some extensions)
      onFileLoaded(result, file.name, file.type || (isText ? 'text/plain' : 'application/octet-stream'));
    };

    if (isText) {
        reader.readAsText(file);
    } else {
        reader.readAsDataURL(file);
    }
  };

  return (
    <motion.div
      initial={{ scale: 0.9, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      whileHover={{ scale: 1.01, boxShadow: "0 20px 40px rgba(0,0,0,0.2)" }}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`
        relative w-full h-52 rounded-3xl glass-panel border-2 transition-all duration-300 flex flex-col items-center justify-center cursor-pointer overflow-hidden
        ${isDragging ? "border-blue-400 bg-blue-500/10" : "border-white/10 hover:border-white/30"}
      `}
    >
      <input
        type="file"
        className="absolute inset-0 opacity-0 cursor-pointer z-10"
        onChange={handleFileInput}
        accept=".eml,.txt,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.mp3"
      />
      
      <AnimatePresence mode="wait">
        {fileLoadedName ? (
            <motion.div
                key="loaded"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="text-center z-0"
            >
                <div className="w-12 h-12 mx-auto bg-green-500/20 rounded-xl flex items-center justify-center mb-3 text-2xl">
                    📄
                </div>
                <h3 className="text-lg font-bold text-white mb-1">File Ready</h3>
                <p className="text-white/60 text-xs font-mono bg-black/20 px-3 py-1 rounded-lg inline-block">{fileLoadedName}</p>
            </motion.div>
        ) : (
            <motion.div
                key="empty"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="text-center z-0"
            >
                <div className={`w-12 h-12 mx-auto rounded-xl flex items-center justify-center mb-3 text-2xl transition-colors ${isDragging ? 'bg-blue-500 text-white' : 'bg-white/10 text-white/50'}`}>
                    {isDragging ? <FileText/> : <Shield/>}
                </div>
                <h3 className="text-lg font-bold text-white mb-2">Drop Artifacts for Analysis</h3>
                <p className="text-white/50 text-xs max-w-xs mx-auto">
                    Supports EML • PDF • Office Macros • Audio (Vishing)
                </p>
            </motion.div>
        )}
      </AnimatePresence>
      <div className="absolute inset-0 bg-gradient-to-tr from-blue-500/5 to-purple-500/5 pointer-events-none" />
    </motion.div>
  );
};

const CivilianView = ({ result }: { result: AnalysisResult }) => {
    const isMalicious = result.verdict === "Malicious";
    const isSuspicious = result.verdict === "Suspicious";

    let bgGradient = "from-green-500/20 to-emerald-500/5";
    let icon = "✅";
    let titleColor = "text-emerald-400";
    
    if (isMalicious) {
        bgGradient = "from-red-500/20 to-pink-500/5";
        icon = "🚨";
        titleColor = "text-red-400";
    } else if (isSuspicious) {
        bgGradient = "from-amber-500/20 to-orange-500/5";
        icon = "⚠️";
        titleColor = "text-amber-400";
    }

    return (
        <motion.div 
            className={`w-full max-w-2xl mx-auto glass-panel rounded-[40px] p-10 overflow-hidden relative border border-white/10 shadow-2xl`}
        >
            <div className={`absolute inset-0 bg-gradient-to-b ${bgGradient} opacity-50`}></div>
            
            <div className="relative z-10 flex flex-col items-center text-center">
                <div className="text-8xl mb-6 filter drop-shadow-2xl animate-bounce-slow">{icon}</div>
                
                <h2 className={`text-4xl md:text-5xl font-bold mb-4 ${titleColor}`}>
                    {result.verdict === "Clean" ? "Safe to Open" : result.verdict === "Malicious" ? "Do Not Open" : "Be Careful"}
                </h2>
                
                <p className="text-xl text-white/90 leading-relaxed mb-8 font-medium">
                    {result.simple_analysis.explanation}
                </p>

                {/* Recommendations Section */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 w-full mt-6">
                    {/* DOs */}
                    <div className="bg-green-500/10 border border-green-500/20 rounded-2xl p-6 text-left relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-4 opacity-10">
                            <CheckCircle className="w-16 h-16 text-green-400" />
                        </div>
                        <h3 className="text-green-400 font-bold mb-4 flex items-center gap-2 uppercase tracking-widest text-xs relative z-10">
                            <span className="w-2 h-2 rounded-full bg-green-400"></span>
                            Recommended Actions
                        </h3>
                        <ul className="space-y-3 relative z-10">
                            {result.recommendations.do.map((item, i) => (
                                <li key={i} className="flex items-start gap-3 text-green-100 text-sm">
                                    <CheckCircle className="w-5 h-5 text-green-400 shrink-0 mt-0.5" />
                                    <span>{item}</span>
                                </li>
                            ))}
                        </ul>
                    </div>

                    {/* DONTs */}
                    <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-6 text-left relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-4 opacity-10">
                            <XCircle className="w-16 h-16 text-red-400" />
                        </div>
                        <h3 className="text-red-400 font-bold mb-4 flex items-center gap-2 uppercase tracking-widest text-xs relative z-10">
                            <span className="w-2 h-2 rounded-full bg-red-400"></span>
                            Avoid
                        </h3>
                        <ul className="space-y-3 relative z-10">
                            {result.recommendations.dont.map((item, i) => (
                                <li key={i} className="flex items-start gap-3 text-red-100 text-sm">
                                    <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                                    <span>{item}</span>
                                </li>
                            ))}
                        </ul>
                    </div>
                </div>
            </div>
        </motion.div>
    );
}

const AnalystView = ({ result }: { result: AnalysisResult }) => {
    const isMalicious = result.verdict === "Malicious";
    const isSuspicious = result.verdict === "Suspicious";
  
    let accentGradient = "from-green-400 to-emerald-600";
    let statusColor = "text-emerald-300";
  
    if (isMalicious) {
      accentGradient = "from-red-500 to-pink-600";
      statusColor = "text-red-300";
    } else if (isSuspicious) {
      accentGradient = "from-amber-400 to-orange-500";
      statusColor = "text-amber-300";
    }
  
    const container = {
      hidden: { opacity: 0 },
      show: { opacity: 1, transition: { staggerChildren: 0.05 } }
    };
  
    const item = {
      hidden: { y: 20, opacity: 0, scale: 0.95 },
      show: { y: 0, opacity: 1, scale: 1 }
    };
  
    // Gauge calculations
    const radius = 56;
    const circumference = 2 * Math.PI * radius;
    const targetOffset = circumference - (result.confidence_score / 100) * circumference;
  
    return (
      <motion.div 
        variants={container}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
      >
        {/* 1. Verdict Card (Top Left) */}
        <motion.div variants={item} className="md:col-span-2 glass-panel rounded-3xl p-8 relative overflow-hidden group">
          <div className={`absolute inset-0 bg-gradient-to-br ${accentGradient} opacity-10 group-hover:opacity-20 transition-opacity duration-500`}></div>
          <div className="relative z-10">
            <div className="flex justify-between items-start mb-4">
              <span className="text-xs uppercase tracking-widest text-white/40 font-bold font-mono">SOC Verdict</span>
              <span className={`px-3 py-1 rounded text-xs font-mono font-bold uppercase bg-black/40 border border-white/10 ${statusColor}`}>{result.verdict}</span>
            </div>
            <h2 className="text-4xl font-bold text-white mb-3 tracking-tight">{result.verdict.toUpperCase()}</h2>
            <p className="text-white/70 text-sm leading-relaxed font-mono border-l-2 border-white/20 pl-4">
              {result.expert_analysis.technical_summary}
            </p>
          </div>
        </motion.div>
  
        {/* 2. Confidence Gauge (Top Right) */}
        <motion.div variants={item} className="glass-panel rounded-3xl p-6 flex flex-col items-center justify-center relative">
           <span className="text-xs uppercase tracking-widest text-white/40 font-bold font-mono mb-4">AI Confidence</span>
           <div className="relative w-32 h-32">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 128 128">
                  <defs>
                      <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                          <stop offset="0%" stopColor="#22d3ee" /> 
                          <stop offset="100%" stopColor="#3b82f6" /> 
                      </linearGradient>
                  </defs>
                  <circle cx="64" cy="64" r={radius} stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                  <motion.circle 
                      cx="64" cy="64" r={radius} stroke="url(#gaugeGradient)" strokeWidth="8" fill="none" strokeLinecap="round"
                      strokeDasharray={circumference}
                      initial={{ strokeDashoffset: circumference }}
                      animate={{ strokeDashoffset: targetOffset }}
                      transition={{ duration: 1.5, ease: "easeOut" }}
                      style={{ filter: "drop-shadow(0 0 4px rgba(59, 130, 246, 0.5))" }}
                  />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-2xl font-bold text-white font-mono">{result.confidence_score}%</span>
              </div>
           </div>
        </motion.div>

        {/* 3. Threat Map (Middle - NEW) */}
        <motion.div variants={item} className="md:col-span-3 h-80">
            <ThreatMap ip={result.sender_metadata.ip_address} />
        </motion.div>

        {/* 4. Threat Intelligence Grid (Middle) */}
        <motion.div variants={item} className="md:col-span-3 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="glass-panel rounded-3xl p-6">
                <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2 font-mono uppercase text-white/50">
                    <Tooltip term="IOCs" definition="Indicators of Compromise: Artifacts observed on a network that indicate a computer intrusion.">
                        Indicators of Compromise
                    </Tooltip>
                </h3>
                <div className="space-y-2">
                    {result.red_flags.map((flag, idx) => (
                        <div key={idx} className="flex items-start gap-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                            <span className="text-red-400 font-mono text-xs mt-0.5">[!]</span>
                            <span className="text-sm text-red-100 font-mono">{flag}</span>
                        </div>
                    ))}
                </div>
            </div>

            <div className="glass-panel rounded-3xl p-6">
                <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2 font-mono uppercase text-white/50">
                    Technical Metadata
                </h3>
                <div className="space-y-4 font-mono text-xs">
                    <div>
                        <div className="text-white/30 mb-1">MITRE ATT&CK TACTICS</div>
                        <div className="flex flex-wrap gap-2">
                            {result.expert_analysis.mitre_attack_ids.length > 0 ? result.expert_analysis.mitre_attack_ids.map(id => (
                                <Tooltip key={id} term={id} definition="MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.">
                                    <span className="px-2 py-1 bg-purple-500/20 border border-purple-500/30 text-purple-300 rounded hover:bg-purple-500/30 transition-colors">
                                        {id}
                                    </span>
                                </Tooltip>
                            )) : <span className="text-white/20">None identified</span>}
                        </div>
                    </div>
                    <div>
                        <div className="text-white/30 mb-1">
                            <Tooltip term="Authentication" definition="Protocols like SPF, DKIM, and DMARC used to verify sender identity.">
                                AUTHENTICATION (SPF/DKIM)
                            </Tooltip>
                        </div>
                        <div className="p-2 bg-black/30 rounded text-white/70 border border-white/5">
                            {result.expert_analysis.spf_dkim_dmarc_status}
                        </div>
                    </div>
                     <div>
                        <div className="text-white/30 mb-1">SENDER</div>
                        <div className="text-white/90 break-all">{result.headers.from}</div>
                    </div>
                </div>
            </div>
        </motion.div>

        {/* 5. Attacker Replication Code (Bottom Full) */}
        <motion.div variants={item} className="md:col-span-3 glass-panel rounded-3xl p-0 overflow-hidden border border-white/10 flex flex-col">
            <div className="px-6 py-4 bg-black/40 border-b border-white/5 flex justify-between items-center">
                <h3 className="text-sm font-mono text-blue-400 font-bold flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                    ATTACK_REPLICATION.PY
                </h3>
                <span className="text-[10px] text-white/30 uppercase tracking-widest">Educational Use Only</span>
            </div>
            <div className="p-6 bg-[#0d0d0d] overflow-x-auto">
                <pre className="font-mono text-xs md:text-sm leading-relaxed">
                    <code className="text-gray-300">
                        {result.attacker_replication_code}
                    </code>
                </pre>
            </div>
        </motion.div>
      </motion.div>
    );
};

const QuizModal = ({ onClose }: { onClose: () => void }) => {
    const [quizData, setQuizData] = useState<QuizScenario | null>(null);
    const [loading, setLoading] = useState(true);
    const [result, setResult] = useState<"correct" | "wrong" | null>(null);
    const [score, setScore] = useState(0);

    const loadQuestion = async () => {
        setLoading(true);
        setResult(null);
        setQuizData(null);
        try {
             const response = await ai.models.generateContent({
                model: "gemini-2.5-flash",
                contents: "Generate a unique email scenario for a phishing awareness quiz.",
                config: {
                    systemInstruction: `Generate a unique email scenario. It can be either SAFE or PHISHING (50/50 chance).`,
                    responseMimeType: "application/json",
                    responseSchema: quizSchema,
                    temperature: 1, // High temperature for variety
                },
            });
            if (response.text) {
                setQuizData(JSON.parse(response.text));
            }
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    // Load initial question
    React.useEffect(() => {
        loadQuestion();
    }, []);

    const handleGuess = (isPhishingGuess: boolean) => {
        if (!quizData) return;
        const isCorrect = isPhishingGuess === quizData.is_phishing;
        setResult(isCorrect ? "correct" : "wrong");
        if (isCorrect) setScore(s => s + 1);
    };

    return (
        <motion.div 
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4"
        >
            <motion.div 
                initial={{ scale: 0.9, y: 20 }} animate={{ scale: 1, y: 0 }}
                className="glass-panel w-full max-w-xl rounded-3xl overflow-hidden shadow-2xl border border-yellow-500/20"
            >
                {/* Header */}
                <div className="bg-yellow-500/10 p-4 flex justify-between items-center border-b border-yellow-500/20">
                    <div className="flex items-center gap-2 text-yellow-400 font-bold">
                        <Gamepad2 size={20}/> 
                        <span>PHISHING DOJO</span>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-3 bg-black/20 px-3 py-1 rounded-lg">
                             <div className="text-xs text-yellow-200/50 font-mono">SCORE</div>
                             <div className="font-mono text-xl text-yellow-400 font-bold">{score}</div>
                        </div>
                        <button onClick={onClose} className="text-white/30 hover:text-white transition-colors">
                            <XCircle size={24}/>
                        </button>
                    </div>
                </div>

                <div className="p-8">
                    {loading ? (
                        <div className="py-12 flex flex-col items-center justify-center space-y-4">
                            <div className="w-8 h-8 border-2 border-yellow-500/30 border-t-yellow-500 rounded-full animate-spin"></div>
                            <div className="text-yellow-500/50 text-xs font-mono animate-pulse">GENERATING SCENARIO...</div>
                        </div>
                    ) : quizData ? (
                        <>
                            {/* Email Scenario Card */}
                            <div className="bg-black/40 rounded-xl p-6 mb-8 font-mono text-sm border-l-4 border-slate-700 relative overflow-hidden">
                                <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                                    <Shield size={64} />
                                </div>
                                <div className="mb-2 flex items-center gap-2">
                                    <span className="text-slate-500 text-xs uppercase tracking-wider">From:</span> 
                                    <span className="text-white bg-white/5 px-2 py-0.5 rounded border border-white/5">{quizData.sender}</span>
                                </div>
                                <div className="mb-6 flex items-center gap-2">
                                    <span className="text-slate-500 text-xs uppercase tracking-wider">Subject:</span> 
                                    <span className="text-white font-bold">{quizData.subject}</span>
                                </div>
                                <div className="text-slate-200 whitespace-pre-wrap leading-relaxed border-t border-white/5 pt-4">
                                    {quizData.body}
                                </div>
                            </div>

                            {/* Interaction Area */}
                            {!result ? (
                                <div className="grid grid-cols-2 gap-4">
                                    <button 
                                        onClick={() => handleGuess(false)} 
                                        className="group relative overflow-hidden bg-green-500/10 hover:bg-green-500/20 border border-green-500/30 text-green-400 py-6 rounded-2xl font-bold text-lg transition-all"
                                    >
                                        <span className="relative z-10 flex flex-col items-center gap-2">
                                            <CheckCircle size={24} />
                                            LEGITIMATE
                                        </span>
                                    </button>
                                    <button 
                                        onClick={() => handleGuess(true)} 
                                        className="group relative overflow-hidden bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 py-6 rounded-2xl font-bold text-lg transition-all"
                                    >
                                         <span className="relative z-10 flex flex-col items-center gap-2">
                                            <AlertTriangle size={24} />
                                            PHISHING
                                        </span>
                                    </button>
                                </div>
                            ) : (
                                <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="text-center">
                                    <div className={`text-4xl font-bold mb-4 flex items-center justify-center gap-3 ${result === 'correct' ? 'text-green-400' : 'text-red-400'}`}>
                                        {result === 'correct' ? <CheckCircle size={40} /> : <XCircle size={40} />}
                                        {result === 'correct' ? 'CORRECT!' : 'MISSED IT!'}
                                    </div>
                                    <div className="bg-white/5 rounded-xl p-6 mb-8 text-left border border-white/10">
                                        <div className="text-xs uppercase tracking-widest text-white/40 mb-2 font-bold">Analysis</div>
                                        <p className="text-white/90 leading-relaxed">{quizData.clues}</p>
                                    </div>
                                    <button 
                                        onClick={loadQuestion} 
                                        className="bg-yellow-500 text-black px-8 py-3 rounded-full font-bold hover:bg-yellow-400 transition-colors shadow-lg shadow-yellow-500/20"
                                    >
                                        NEXT ROUND
                                    </button>
                                </motion.div>
                            )}
                        </>
                    ) : (
                        <div className="text-center text-red-400">Failed to generate quiz. Please check API connection.</div>
                    )}
                </div>
            </motion.div>
        </motion.div>
    );
};

const Blob = ({ color, style, isAnalyst }: { color: string; style: any; isAnalyst: boolean }) => {
    return (
        <motion.div
            className="absolute rounded-full filter blur-[80px] z-0 opacity-60"
            initial={false}
            animate={{
                backgroundColor: color,
                ...style
            }}
            transition={{ duration: 2, ease: "easeInOut" }}
        />
    )
}

const App = () => {
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [fileMimeType, setFileMimeType] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isAnalystMode, setIsAnalystMode] = useState(false);
  const [showQuiz, setShowQuiz] = useState(false);

  const handleFileLoaded = (content: string, name: string, mimeType: string) => {
    setFileContent(content);
    setFileName(name);
    setFileMimeType(mimeType);
    setAnalysis(null);
    setError(null);
  };

  const analyzeEmail = async () => {
    if (!fileContent) {
      setError("No file content detected.");
      return;
    }
    
    setIsLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const systemInstruction = `
        You are an elite cybersecurity analyst. Analyze the provided file (Email, Document, or Audio) for phishing and malicious intent.
        
        For PDFs and Office files, scan for suspicious macros, embedded JavaScript, and fake login overlays.
        For Audio (MP3), analyze the speech for Vishing (Voice Phishing) tactics like urgency, fake authority (IRS/Police), and background noise fabrication.
        For Emails (.eml/text), analyze headers, SPF/DKIM, and body content.

        Provide a dual-layer analysis: one simple for laypeople, one expert for SOC analysts.
        Crucially, provide specific recommendations in two lists: 'do' (actions to take) and 'dont' (actions to avoid).
        Additionally, analyze the headers/metadata to find the deepest originating IP address and extract it into the sender_metadata field along with estimated country and proxy detection.
      `;

      let contentsPayload: any;

      if (fileMimeType && fileMimeType !== "text/plain" && fileMimeType !== "message/rfc822") {
          // Binary File Handling (PDF, Office, Audio)
          const cleanBase64 = fileContent.split(",")[1]; // Strip "data:application/pdf;base64," prefix
          contentsPayload = {
              parts: [
                  {
                      inlineData: {
                          mimeType: fileMimeType,
                          data: cleanBase64
                      }
                  }
              ]
          };
      } else {
          // Text/Email Handling
          contentsPayload = fileContent;
      }

      const response = await ai.models.generateContent({
        model: "gemini-2.5-flash",
        contents: contentsPayload,
        config: {
          systemInstruction,
          responseMimeType: "application/json",
          responseSchema: analysisSchema,
          temperature: 0.2, 
        },
      });

      const text = response.text;
      if (text) {
        setAnalysis(JSON.parse(text) as AnalysisResult);
      } else {
        throw new Error("Empty response from AI.");
      }
    } catch (err) {
      console.error(err);
      setError("Analysis failed. Please check your API key or file format.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <motion.div 
       className="min-h-screen pb-20 selection:bg-purple-500/30 selection:text-white relative overflow-hidden"
       animate={{
         backgroundImage: isAnalystMode 
           ? "linear-gradient(to right, #0f2027, #203a43, #2c5364)" 
           : "linear-gradient(to right, #1f2937, #374151, #111827)"
       }}
       transition={{ duration: 1.5, ease: "easeInOut" }}
    >
      {/* Dynamic Blobs */}
      <Blob 
        isAnalyst={isAnalystMode}
        color={isAnalystMode ? "#023e8a" : "#7b2ff7"}
        style={{ top: "-10%", left: "-10%", width: "500px", height: "500px" }}
      />
      <Blob 
        isAnalyst={isAnalystMode}
        color={isAnalystMode ? "#00b4d8" : "#f107a3"}
        style={{ bottom: "-10%", right: "-10%", width: "600px", height: "600px" }}
      />
      <Blob 
        isAnalyst={isAnalystMode}
        color={isAnalystMode ? "#0077b6" : "#4facfe"}
        style={{ top: "40%", left: "40%", width: "400px", height: "400px" }}
      />

      <Header onOpenQuiz={() => setShowQuiz(true)} />
      
      <main className="container mx-auto max-w-4xl px-4 py-8 relative z-10">
        
        <ModeToggle isAnalyst={isAnalystMode} toggle={() => setIsAnalystMode(!isAnalystMode)} />

        {/* Input Section */}
        <AnimatePresence>
            {!analysis && (
                <motion.section 
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    layout
                    className="space-y-8 mb-12"
                >
                    <div className="text-center space-y-4">
                        <h2 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-white/60">
                            Multimodal Forensic Scanner
                        </h2>
                        <p className="text-white/50 text-sm max-w-lg mx-auto">
                            Advanced forensic engine for multimodal threat detection. Instantly analyze emails, weaponized documents, and voice intercepts to expose adversary infrastructure and intent.
                        </p>
                    </div>

                    <FileDropZone onFileLoaded={handleFileLoaded} fileLoadedName={fileName} />
                    
                    {fileContent && (
                        <div className="flex justify-center">
                            <motion.button
                                type="button"
                                onClick={analyzeEmail}
                                disabled={isLoading}
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                className={`
                                    px-8 py-3 rounded-full font-bold text-base shadow-lg shadow-purple-500/20
                                    bg-gradient-to-r from-blue-600 to-purple-600 text-white
                                    hover:shadow-xl hover:shadow-purple-500/40 transition-all
                                    disabled:opacity-70 disabled:cursor-not-allowed
                                    flex items-center gap-2
                                `}
                            >
                                {isLoading ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                        Analyzing...
                                    </>
                                ) : (
                                    <>
                                        Run Analysis
                                        <span>✨</span>
                                    </>
                                )}
                            </motion.button>
                        </div>
                    )}
                </motion.section>
            )}
        </AnimatePresence>

        {/* Error Display */}
        <AnimatePresence>
            {error && (
                <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="mb-8 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-200 text-center text-sm"
                >
                    {error}
                </motion.div>
            )}
        </AnimatePresence>

        {/* Results Section */}
        <AnimatePresence>
            {analysis && (
                <motion.section 
                    initial={{ opacity: 0, y: 50 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 50 }}
                    transition={{ type: "spring", stiffness: 100, damping: 20 }}
                    className="w-full relative"
                >
                    <motion.div layout className="relative">
                        <AnimatePresence mode="wait">
                            {isAnalystMode ? (
                                <motion.div
                                    key="analyst"
                                    initial={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
                                    animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
                                    exit={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
                                    transition={{ duration: 0.4, ease: [0.23, 1, 0.32, 1] }}
                                >
                                    <AnalystView result={analysis} />
                                </motion.div>
                            ) : (
                                <motion.div
                                    key="civilian"
                                    initial={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
                                    animate={{ opacity: 1, scale: 1, filter: "blur(0px)" }}
                                    exit={{ opacity: 0, scale: 0.95, filter: "blur(10px)" }}
                                    transition={{ duration: 0.4, ease: [0.23, 1, 0.32, 1] }}
                                >
                                    <CivilianView result={analysis} />
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </motion.div>
                    
                    {/* Reset Button */}
                    <motion.div layout className="flex justify-center mt-12">
                        <button 
                            onClick={() => { setAnalysis(null); setFileContent(null); setFileName(null); }}
                            className="text-white/30 hover:text-white text-sm transition-colors uppercase tracking-widest font-mono font-bold"
                        >
                            Analyze Another File
                        </button>
                    </motion.div>
                </motion.section>
            )}
        </AnimatePresence>

        {/* Quiz Modal Overlay */}
        <AnimatePresence>
            {showQuiz && <QuizModal onClose={() => setShowQuiz(false)} />}
        </AnimatePresence>

      </main>
    </motion.div>
  );
};

const root = createRoot(document.getElementById("root")!);
root.render(<App />);