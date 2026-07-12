// Mirrors a real pattern: an API key from form state is persisted to
// localStorage on save. Real finding on dgero22/digital-rolecraft was
// wrongly discarded by the old line-by-line anti-hallucination check
// because the model's evidence spanned two lines (the `if` and the
// `localStorage.setItem` call below it).
import { useRef, useState } from 'react'

export function usePersonaForm() {
  const [formData, setFormData] = useState({ geminiApiKey: '' })
  const avatarFileInputRef = useRef<HTMLInputElement>(null)

  const handleSave = () => {
    if (formData.geminiApiKey) {
      localStorage.setItem('gemini_api_key', formData.geminiApiKey)
    }
  }

  return { formData, setFormData, handleSave }
}
