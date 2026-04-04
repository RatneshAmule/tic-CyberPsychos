import { NextRequest, NextResponse } from 'next/server';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

const CONFIG_DIR = '/tmp/recon-x';
const CONFIG_FILE = join(CONFIG_DIR, 'ai-settings.json');

function getDefaultSettings() {
  return {
    apiKey: process.env.NVIDIA_API_KEY || '',
    model: process.env.AI_MODEL || 'moonshotai/kimi-k2.5',
    apiUrl: process.env.NVIDIA_API_URL || 'https://integrate.api.nvidia.com/v1/chat/completions',
    maxTokens: 16384,
    temperature: 1.0,
    topP: 1.0,
    stream: true,
  };
}

function readSettings() {
  try {
    if (existsSync(CONFIG_FILE)) {
      const raw = readFileSync(CONFIG_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      return { ...getDefaultSettings(), ...parsed };
    }
  } catch (err) {
    console.error('[JURI-X] Failed to read AI settings:', err);
  }
  return getDefaultSettings();
}

function saveSettings(settings: Record<string, unknown>) {
  try {
    if (!existsSync(CONFIG_DIR)) {
      mkdirSync(CONFIG_DIR, { recursive: true });
    }
    writeFileSync(CONFIG_FILE, JSON.stringify(settings, null, 2));
    return true;
  } catch (err) {
    console.error('[JURI-X] Failed to save AI settings:', err);
    return false;
  }
}

// GET — Return current AI settings (apiKey masked)
export async function GET() {
  try {
    const settings = readSettings();

    // Mask the API key for security
    const maskedKey = settings.apiKey
      ? settings.apiKey.substring(0, 8) + '****' + settings.apiKey.substring(settings.apiKey.length - 4)
      : '';

    // Check if key is configured
    const isConfigured = settings.apiKey &&
      settings.apiKey !== 'nvapi-YOUR_API_KEY_HERE' &&
      !settings.apiKey.includes('YOUR_API_KEY');

    return NextResponse.json({
      model: settings.model,
      apiUrl: settings.apiUrl,
      maxTokens: settings.maxTokens,
      temperature: settings.temperature,
      topP: settings.topP,
      stream: settings.stream,
      maskedApiKey: maskedKey,
      isConfigured,
    });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to read settings' }, { status: 500 });
  }
}

// POST — Save AI settings (full API key accepted)
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const currentSettings = readSettings();

    const newSettings = {
      ...currentSettings,
      apiKey: body.apiKey || currentSettings.apiKey,
      model: body.model || currentSettings.model,
      apiUrl: body.apiUrl || currentSettings.apiUrl,
      maxTokens: body.maxTokens ?? currentSettings.maxTokens,
      temperature: body.temperature ?? currentSettings.temperature,
      topP: body.topP ?? currentSettings.topP,
      stream: body.stream ?? currentSettings.stream,
    };

    const saved = saveSettings(newSettings);
    if (!saved) {
      return NextResponse.json({ error: 'Failed to save settings' }, { status: 500 });
    }

    // Mask key for response
    const maskedKey = newSettings.apiKey
      ? newSettings.apiKey.substring(0, 8) + '****' + newSettings.apiKey.substring(newSettings.apiKey.length - 4)
      : '';

    return NextResponse.json({
      success: true,
      model: newSettings.model,
      maskedApiKey: maskedKey,
    });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to save settings' }, { status: 500 });
  }
}

// DELETE — Reset to defaults
export async function DELETE() {
  try {
    const defaults = getDefaultSettings();
    const saved = saveSettings(defaults);
    return NextResponse.json({ success: saved, reset: true });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to reset settings' }, { status: 500 });
  }
}
