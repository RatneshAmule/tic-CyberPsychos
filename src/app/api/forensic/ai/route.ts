import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { messages, apiKey, model, stream } = body;

    // Get config from .env first, fallback to request body
    const resolvedApiKey = apiKey || process.env.NVIDIA_API_KEY;
    const resolvedModel = model || process.env.AI_MODEL || 'moonshotai/kimi-k2.5';
    const apiUrl = process.env.NVIDIA_API_URL || 'https://integrate.api.nvidia.com/v1/chat/completions';

    if (!resolvedApiKey || resolvedApiKey === 'nvapi-YOUR_API_KEY_HERE' || resolvedApiKey.includes('YOUR_API_KEY')) {
      return NextResponse.json(
        { error: 'NVIDIA API key not configured. Go to Settings tab to add your API key.' },
        { status: 400 }
      );
    }

    // Build system prompt for forensic AI
    const forensicSystemPrompt = `You are JURI-X AI, an advanced forensic intelligence assistant integrated into a Digital Forensics & Incident Response (DFIR) platform. You specialize in:

CRIMINAL FORENSIC ANALYSIS:
- Digital evidence analysis and interpretation
- Timeline reconstruction and event correlation
- Malware analysis and behavioral indicators
- Network forensics and traffic analysis
- Memory forensics and process analysis
- File system analysis and artifact recovery
- Log analysis and event correlation

EXPERTISE AREAS:
- Windows forensics (Registry, Prefetch, Event Logs, Shellbags, Jump Lists, USN Journal)
- Linux forensics (bash_history, syslog, auth.log, cron, systemd journals)
- Mobile forensics (Android/iOS artifacts, app data extraction)
- Network forensics (PCAP analysis, DNS logs, firewall logs, proxy logs)
- Browser forensics (Chrome, Firefox, Safari history, cookies, cached data)
- Disk forensics (file carving, slack space, MFT analysis)
- Anti-forensics detection (secure deletion, encryption, steganography)
- Incident response (IOC extraction, threat hunting, malware triage)
- MITRE ATT&CK framework mapping
- Chain of custody procedures

COMMUNICATION STYLE:
- Be precise, technical, and evidence-based
- Reference specific forensic artifacts and tools when relevant
- Use structured analysis when explaining complex topics
- Always mention confidence levels and limitations
- When given forensic data, provide actionable investigation steps
- Format output with clear sections, bullet points, and code blocks when needed
- Respond in the same language the user uses

IMPORTANT: If the user shares forensic evidence data (logs, file hashes, IP addresses, etc.), analyze it thoroughly and provide investigative insights. Do NOT make up evidence - only analyze what is provided.`;

    // Prepend system message
    const fullMessages = [
      { role: 'system', content: forensicSystemPrompt },
      ...(messages || [])
    ];

    // Make request to NVIDIA API
    const nvidiaPayload: Record<string, unknown> = {
      model: resolvedModel,
      messages: fullMessages,
      max_tokens: 16384,
      temperature: 1.0,
      top_p: 1.0,
      stream: stream || false,
    };

    const nvidiaHeaders: Record<string, string> = {
      'Authorization': `Bearer ${resolvedApiKey}`,
      'Content-Type': 'application/json',
    };

    if (stream) {
      nvidiaHeaders['Accept'] = 'text/event-stream';
    } else {
      nvidiaHeaders['Accept'] = 'application/json';
    }

    // Handle streaming
    if (stream) {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: nvidiaHeaders,
        body: JSON.stringify(nvidiaPayload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('[JURI-X AI] NVIDIA API error:', response.status, errorText);
        return NextResponse.json(
          { error: `NVIDIA API error: ${response.status} - ${errorText.substring(0, 200)}` },
          { status: response.status }
        );
      }

      // Stream the response back
      const encoder = new TextEncoder();
      const streamResponse = new ReadableStream({
        async start(controller) {
          const reader = response.body?.getReader();
          if (!reader) {
            controller.close();
            return;
          }

          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              controller.enqueue(value);
            }
          } catch (err) {
            console.error('[JURI-X AI] Stream error:', err);
          } finally {
            controller.close();
          }
        },
      });

      return new Response(streamResponse, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    }

    // Non-streaming response
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: nvidiaHeaders,
      body: JSON.stringify(nvidiaPayload),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[JURI-X AI] NVIDIA API error:', response.status, errorText);
      return NextResponse.json(
        { error: `NVIDIA API error: ${response.status} - ${errorText.substring(0, 200)}` },
        { status: response.status }
      );
    }

    const data = await response.json();

    // Extract and return the AI response
    const aiMessage = data.choices?.[0]?.message?.content || '';
    const finishReason = data.choices?.[0]?.finish_reason || '';
    const usage = data.usage || null;

    return NextResponse.json({
      message: aiMessage,
      finishReason,
      usage,
      model: resolvedModel,
    });
  } catch (error: unknown) {
    const err = error as Error;
    console.error('[JURI-X AI] Error:', err);
    return NextResponse.json(
      { error: `AI request failed: ${err.message}` },
      { status: 500 }
    );
  }
}
