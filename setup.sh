#!/bin/bash
# ChainSight one-click setup for Find Evil! hackathon
set -e

echo "Setting up ChainSight..."

# Create .claude directory
mkdir -p ~/.claude/skills
mkdir -p /cases/demo/{analysis,exports,reports}

# Clone repo if not already done
if [ ! -d ~/chainsight ]; then
    git clone https://github.com/Gideon145/chainsight.git ~/chainsight
fi

# Copy skills and config
cp ~/chainsight/CLAUDE.md ~/.claude/CLAUDE.md
cp -r ~/chainsight/skills/* ~/.claude/skills/

# Find and link sample case data
if [ -d /cases/srl ]; then
    ln -sf /cases/srl/* /cases/demo/ 2>/dev/null || true
elif [ -d /cases/SRL ]; then
    ln -sf /cases/SRL/* /cases/demo/ 2>/dev/null || true
fi

echo ""
echo "Done! Now run these 3 commands:"
echo ""
echo "  export ANTHROPIC_API_KEY=your-key-here"
echo "  cd /cases/demo"
echo "  claude"
echo ""
echo "Then inside Claude Code, type: /forensic audit"
