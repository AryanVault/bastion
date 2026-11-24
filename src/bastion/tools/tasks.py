"""Tools for scheduled tasks (control C11).

``task_schedule`` creates something that later acts without the owner watching, which makes it
the most persistent thing the model can propose. So it always asks the owner, always needs the
authenticator code, and is refused once the conversation contains untrusted content: text from
an email or web page cannot plant a task. The approval shows the exact name, schedule,
instructions and tools, and is bound to them.

Task tools are never granted to tasks: a task cannot schedule, change or remove tasks.
"""

from typing import Any

from pydantic import Field, ValidationInfo, field_validator

from bastion.autonomy.schedule import EXAMPLES, ScheduleError, local_text, parse_schedule
from bastion.autonomy.tasks import (
    MAX_GRANTED_TOOLS,
    TaskError,
    TaskSpec,
    TaskStore,
    is_task_id,
    render_listing,
    validate_instructions,
    validate_name,
    validate_tools,
)
from bastion.llm.types import ToolSpec
from bastion.tools.base import RiskTier, Tool, ToolArgs, ToolContext, ToolError, ToolOutput, Trust

TASK_TOOLS = frozenset({"task_schedule", "task_list", "task_remove"})
SOURCE = "tasks"


def _readable(exc: TaskError | ScheduleError) -> ValueError:
    return ValueError(str(exc))


class TaskScheduleArgs(ToolArgs):
    name: str = Field(description="A short name for the task, one line.")
    schedule: str = Field(description=f"When it runs, in the owner's local time: {EXAMPLES}.")
    instructions: str = Field(
        description=(
            "What to do on each run, as a request to you. Each run starts fresh, without this "
            "conversation, so make it self-contained."
        )
    )
    tools: list[str] = Field(
        default_factory=list,
        max_length=MAX_GRANTED_TOOLS,
        description="The only tools each run may use. Grant as few as the task needs.",
    )

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        try:
            return validate_name(value)
        except TaskError as exc:
            raise _readable(exc) from None

    @field_validator("schedule")
    @classmethod
    def _schedule(cls, value: str) -> str:
        try:
            return parse_schedule(value).text
        except ScheduleError as exc:
            raise _readable(exc) from None

    @field_validator("instructions")
    @classmethod
    def _instructions(cls, value: str) -> str:
        try:
            return validate_instructions(value)
        except TaskError as exc:
            raise _readable(exc) from None

    @field_validator("tools")
    @classmethod
    def _tools(cls, value: list[str], info: ValidationInfo) -> list[str]:
        context = info.context or {}
        grantable = context.get("grantable")
        if grantable is None:
            return list(dict.fromkeys(value))
        try:
            return list(validate_tools(value, grantable))
        except TaskError as exc:
            raise _readable(exc) from None


class TaskScheduleTool(Tool[TaskScheduleArgs]):
    name = "task_schedule"
    description = (
        "Schedule a recurring task that runs on its own and sends the owner a report after "
        "each run. The owner must approve it with their authenticator code. Only use this when "
        "the owner asks for something to happen regularly."
    )
    args_model = TaskScheduleArgs
    risk = RiskTier.WRITE
    always_ask = True
    step_up = True
    clean_only = True

    def __init__(self, store: TaskStore, grantable: frozenset[str], *, max_tasks: int) -> None:
        self._store = store
        self._grantable = grantable - TASK_TOOLS
        self._max_tasks = max_tasks

    def validation_context(self) -> dict[str, Any]:
        return {"grantable": self._grantable}

    def spec(self) -> ToolSpec:
        allowed = ", ".join(sorted(self._grantable)) or "none"
        base = super().spec()
        return ToolSpec(
            base.name, f"{base.description} Tools a task can use: {allowed}.", base.parameters
        )

    def _new_spec(self, args: TaskScheduleArgs) -> TaskSpec:
        return self._store.new_spec(
            name=args.name,
            schedule=args.schedule,
            instructions=args.instructions,
            tools=args.tools,
            grantable=self._grantable,
            created_via="assistant",
        )

    def describe(self, args: TaskScheduleArgs) -> str:
        try:
            spec = self._new_spec(args)
            first = local_text(self._store.next_run(spec, self._store.now()), self._store.tz)
        except TaskError:
            first = "unknown"
        tools = ", ".join(args.tools) or "no tools"
        # The model-chosen name is left out of this sentence (it could be phrased to mislead);
        # it is shown with the exact arguments below.
        return (
            f"Schedule a new task: {args.schedule} (first run {first}), using {tools}. Every "
            "run follows the instructions below without you watching."
        )

    def audit_view(self, args: TaskScheduleArgs) -> dict[str, Any]:
        view = super().audit_view(args)
        view.update(schedule=args.schedule, tools=list(args.tools))
        return view

    async def run(self, args: TaskScheduleArgs, ctx: ToolContext) -> ToolOutput:
        try:
            task = self._store.add(self._new_spec(args), limit=self._max_tasks)
        except TaskError as exc:
            raise ToolError(f"could not schedule the task: {exc}") from None
        first = local_text(task.next_run, self._store.tz) if task.next_run else "not scheduled"
        return ToolOutput(
            f"Scheduled '{task.name}' (id {task.id}): {task.spec.schedule.text}, first run "
            f"{first}. The owner can list tasks with /tasks, and pause or remove this one on "
            f"their computer with: bastion tasks pause {task.id} / bastion tasks remove {task.id}",
            Trust.TRUSTED,
            SOURCE,
        )


class NoArgs(ToolArgs):
    pass


class TaskListTool(Tool[NoArgs]):
    name = "task_list"
    description = "List the owner's scheduled tasks: names, ids, schedules, next runs and tools."
    args_model = NoArgs
    risk = RiskTier.READ

    def __init__(self, store: TaskStore) -> None:
        self._store = store

    async def run(self, args: NoArgs, ctx: ToolContext) -> ToolOutput:
        # Task definitions were written or approved by the owner, and are sealed: trusted.
        return ToolOutput(
            render_listing(self._store.listing(), self._store.tz), Trust.TRUSTED, SOURCE
        )


class TaskRemoveArgs(ToolArgs):
    task_id: str = Field(description="The task's 8-character id, as shown by task_list.")

    @field_validator("task_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not is_task_id(value):
            raise ValueError("a task id is 8 lowercase hexadecimal characters")
        return value


class TaskRemoveTool(Tool[TaskRemoveArgs]):
    name = "task_remove"
    description = "Remove one of the owner's scheduled tasks for good."
    args_model = TaskRemoveArgs
    risk = RiskTier.WRITE
    always_ask = True  # a task may be the owner's safeguard: never removed unasked

    def __init__(self, store: TaskStore) -> None:
        self._store = store

    def describe(self, args: TaskRemoveArgs) -> str:
        try:
            task = self._store.get(args.task_id)
        except TaskError:
            task = None
        label = f"'{task.name}' ({args.task_id})" if task else args.task_id
        return f"Remove the scheduled task {label}"

    async def run(self, args: TaskRemoveArgs, ctx: ToolContext) -> ToolOutput:
        if not self._store.remove(args.task_id):
            raise ToolError(f"there is no task {args.task_id}")
        return ToolOutput(f"Removed the task {args.task_id}.", Trust.TRUSTED, SOURCE)
